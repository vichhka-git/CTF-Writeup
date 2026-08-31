# Jacobian as a Service — Writeup

## Service

`chall.py` runs under `sage -python`, offering:
1. `Jacobian(f)` on an attacker-supplied bivariate polynomial expression over `GF(p)`.
2. A "bug report" feature: `open(name, "w").write(description)` — **arbitrary path, arbitrary single-line file write**, no filename filtering (only the polynomial expression is character-filtered).

The container also ships:
- `/home/ctf/tes`, compiled from `wut.c`, owned `target:target`, **SGID `target`** (`chmod 2755`). It calls
  `prctl(PR_SET_DUMPABLE,1)` and `prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY)`, then `raise(SIGSTOP)` and loops
  forever — i.e. it deliberately makes itself ptrace-able by anyone despite running with the `target` group.
- `gdb` with `cap_sys_ptrace+ep` (`setcap`), and the container has `SYS_PTRACE`.
- SageMath's `cysignals` crash handler (`cysignals-CSI`), which on a fatal signal spawns
  `subprocess.Popen(["gdb"], stdin=PIPE, stdout=PIPE, stderr=PIPE, env=os.environ)` — **without `-nx`** — and
  pipes its own commands to gdb's stdin. Because `-nx` is absent, gdb auto-sources `$HOME/.gdbinit`
  (`/home/sage/.gdbinit`, `HOME=/home/sage` is set for the `sage` user process) *before* cysignals' own commands
  run. gdb's captured stdout is written straight back to fd 1 — i.e. our TCP socket.
- `/home/ctf/flag.txt`, owner `target:target`, mode `440`.

## Chain

1. Use the bug-report primitive to write a malicious `/home/sage/.gdbinit`.
2. Trigger a genuine SIGSEGV in the Sage process. `Jacobian` docstring itself notes:
   `Jacobian(GF(11)['x,y'](3))` used to segfault ("Check that the following doesn't segmentation fault").
   The polynomial-expression filter only requires characters from `0123456789+-*/^xy ` and that both `x` and `y`
   appear — it does **not** require the *result* to be non-constant. `x-x+y-y+3` passes the filter, parses to the
   constant polynomial `3`, and crashes `Jacobian_of_equation`'s C-level assumptions with a real SIGSEGV
   (confirmed locally against the real `sagemath/sagemath:10.7` image — raw glibc backtrace, not a Python
   exception).
3. cysignals' handler invokes `gdb`, which sources our `.gdbinit` first. Our payload:
   - `subprocess.Popen(["/home/ctf/tes"])` to start the SGID-`target` helper (this process immediately
     `raise(SIGSTOP)`s itself).
   - `gdb.execute("attach %d" % pid)`.
   - `gdb.execute("handle SIGSTOP nostop noprint nopass")` — **required**: without this, `tes`'s pending
     self-inflicted `SIGSTOP` re-triggers during any inferior function call and aborts it
     (`Program received signal SIGSTOP ...`).
   - Inferior calls via `gdb.parse_and_eval`: `mmap` a scratch buffer, `open("/home/ctf/flag.txt", O_RDONLY)`,
     `read` into the buffer — all executed *inside* the `tes` process, which retains its `target` **egid**, so it
     can open the `440 target:target` flag file.
   - Read the bytes back via `gdb.selected_inferior().read_memory(...)` and `gdb.write(...)` them to gdb's own
     stdout, which cysignals relays to our socket.

## Flag

`COMPFEST18{the_jacobian_conjecture_is_false_claude_9RbqdKhrPeJzPVDF}`

## Reproduction

```
python3 solve.py <host> <port> <ctfd_access_token>
```

Requires an active container instance (`/api/v1/containers/request`) and, since the TCP endpoint sits behind
CTFd's auth proxy, a valid `ctfd_...` access token sent as the first line.

## Verified locally

Built and ran the real challenge image (`sagemath/sagemath:10.7` + the provided `Dockerfile`/`wut.c`/`chall.py`)
in a local Docker container before touching the remote instance, to find the crash trigger and validate the
`.gdbinit` payload (including the SIGSTOP handling fix) without burning the 10-minute remote container TTL.

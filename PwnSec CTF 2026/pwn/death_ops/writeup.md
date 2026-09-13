---
title: "Death Ops"
ctf: "PwnSec 2026"
date: 2026-09-12
category: pwn
difficulty: medium
points: 500
flag_format: "flag{...}"
author: "solver"
---

# Death Ops

## Summary

QEMU Linux 4.9.333 guest: stock `blackops` accepts a 96-byte `A-Za-z0-9` payload, then `call`s an RWX page under seccomp (`read`/`write`/`exit` only). The payload plants `lea rsi,[rcx+0x70]; syscall; jmp rsi`, reads a binary prefix at `rwx+0x70`, then a stage-2 at `rwx+0xa0`. Stage-2 reuses the live `/dev/shadowops` AAW: leak module `.text`, patch the one-shot, plant a `current`-cred stub over `shadowops_open`, `jmp` at `shadowops_write`, `cat /flag*`.

`flag{test_flag_for_ctf_challenge}` is the initramfs fallback when `/flag` is missing. It is **not** the solve.

Local proof (workspace rootfs copy only, stock unpatched `blackops`): `pwnsec{d7aa31cfb225c5a6}`.

## Solution

### Stage-1 alphanumeric loader

`read(0, buf, 96)` then memcpy to RWX. Every byte must be `A-Za-z0-9`. `call rax` with `RAX=rwx`.

The 96-byte memcpy fills stub slots with the pad byte, so plant recipes must XOR `initial^opcode`, not the raw opcode. Pair `imul` multiplier `'3'` (`m=0x33`) with pad `'S'` (`0x53`) so the 8-byte plant still fits before the stub at `0x50`. Keep the `'3'` constant at `0x58` (after the stub) so fall-through never executes `inc ecx` and clobbers `rcx`.

Planted stub: `lea rsi,[rcx+0x70]; syscall; jmp rsi`. `rdx=0x30` so the first read lands a 48-byte prefix at `rwx+0x70` and does not overwrite the stub.

### Prefix / stage-2 split

A stage-2 load at `rwx+0x90` overlaps the 48-byte window (`0x70..0x9f`) and clobbers `jmp rsi` mid-instruction (libc-looking SEGV). Stage-2 is therefore read to `rwx+0xa0`. Prefix does `lea r12,[rip]; sub r12,0x77` (first insn at `+0x70`) then `read`/`jmp` there.

### Kernel path (unchanged)

Intel `/sys/module/shadowops/sections/.text`. AAW `.text+0x3b` to nop the `lock xadd`. Plant cred stub on `shadowops_open` only. Last write: `jmp stub` at `.text+0x30`. `write(3,16)` returns via the syscall (KPTI-safe). `execve("/bin/sh", ["sh","-c","cat /flag*"], 0)`.

## Local proof

Workspace-only initrd `agent_workspace/qemu/rootfs.stockflag.cpio.gz` (stock `blackops`, `/flag` = `pwnsec{d7aa31cfb225c5a6}`). Dist `files/dist/` was not edited.

```
python3 agent_workspace/experiments/solve_stock.py
```

Serial excerpt:

```
S2
pwnsec{d7aa31cfb225c5a6}
pwnsec{d7aa31cfb225c5a6}
```

Then `cat` exits as PID 1 and the guest panics. Expected.

## Flag

Organizer instance not used in this pass. Local stock proof:

```
pwnsec{d7aa31cfb225c5a6}
```

---
title: "Hells Bells"
ctf: "CSAW CTF Qualifications 2026"
date: 2026-09-19
category: pwn
difficulty: medium
points: 405
flag_format: "csaw{...}"
author: "solver_6 / solver_4 / cursor-grok-hells-bells"
---

# Hells Bells

## Challenge Information

- **Name:** Hells Bells
- **Category:** Pwn
- **ID:** 25
- **Points:** 405
- **Author:** WubberDuckkie
- **Binary:** `thermite-charge` (PIE, Full RELRO, NX, no canary)
- **Libc:** Ubuntu 20.04 glibc 2.31 (bundled)
- **Flag:** `csaw{wh3n_y0u_r34ch_th3_cr0ssr04ds_d0nt_turn_l3ft}`

## Summary

The inventory manager's `defuse` frees a charge and does **not** clear the
pointer or size. `inspect` and `rewire` still treat that slot as live, so a
freed chunk is both readable and writable. Leak libc from an unsorted-bin
chunk, poison tcache to overwrite `__free_hook` with `system`, then `defuse`
a `/bin/sh` chunk.

The author line is the clue: *"you can't touch a charge once it's defused."*

## Solution

### Step 1: UAF primitive

Menu: plant / defuse / rewire / inspect. `defuse` is `free(charges[i])` with
no NULL. Occupancy checks are pointer-not-NULL, so inspect/rewire operate on
the stale chunk. Confirmed by defusing a filled chunk and inspecting: the
payload becomes tcache/unsorted metadata.

glibc 2.31: tcache has **no safe-linking**, and `__free_hook` still exists.

### Step 2: Leak + tcache poison

1. Plant `0x500` (above tcache max) + a `0x20` guard, defuse the large slot,
   inspect: first 8 bytes are unsorted-bin `fd` = `main_arena+96` =
   `__malloc_hook+0x70`. Require a page-aligned base that resolves `/bin/sh`.
2. Plant two `0x30` chunks, defuse both into tcache, **rewire** the first
   freed chunk so `fd = __free_hook`.
3. Two more `0x30` plants: the second lands on `__free_hook`; write `system`.
4. Plant `/bin/sh` and defuse it → `system("/bin/sh")`.

### Step 3: Reproduce

```bash
python3 agent_workspace/solve.py                 # local
python3 agent_workspace/solve.py HOST:1024       # remote
```

Local: `HB_LOCAL_SHELL_OK` / `SHELL_OK`. Remote (prior instance
`10.0.171.80:1024`): `HB_REMOTE_SHELL_OK` and `cat flag.txt`. CTFd 25:
**already_solved** (flag accepted as correct).

The later instance `10.0.179.175:1024` did not accept TCP from this host
(connect timed out on `csaw-wg`); the flag was already on the scoreboard.

## Flag

```
csaw{wh3n_y0u_r34ch_th3_cr0ssr04ds_d0nt_turn_l3ft}
```

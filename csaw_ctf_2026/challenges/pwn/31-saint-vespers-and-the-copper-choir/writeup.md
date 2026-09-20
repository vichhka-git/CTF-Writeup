---
title: "Saint Vespers and the Copper Choir"
ctf: "CSAW CTF Qualifications 2026"
date: 2026-09-20
category: pwn
difficulty: medium
points: 480
flag_format: "csaw{...}"
author: "cursor-grok-4.6"
---

# Saint Vespers and the Copper Choir

## Challenge Information

- **Name:** Saint Vespers and the Copper Choir
- **Category:** Pwn
- **ID:** 31
- **Points:** 480
- **Libc:** Ubuntu 22.04 glibc 2.35 (bundled `libc.so_3.6` / `ld-2.35.so`)
- **Flag:** `csaw{c0pper_c01ls_s1ng_wh4t_y0u_wr1te}`

## Summary

`vespers` is a glibc 2.35 choir heap manager. `retire` frees the transcript and
the `chorister_t` but never NULLs `choir[idx]`, then writes `active=0` on the
freed struct. `restore` flips `active` on that dangling pointer. A UAF recite
of a 0x500 transcript leaks unsorted-bin `fd` (libc). A later 0x58 transcript
collides with a freed 0x60 `chorister_t`, overwriting `sing` with `system` and
`name` with `/bin/sh`. Final Performance is `sing(self)`.

## Solution

### Step 1: Bug

`chorister_t` is 0x54 bytes, allocated as `malloc(sizeof)` → 0x60 chunk:

| Offset | Field |
| --- | --- |
| `+0x00` | `name[0x38]` |
| `+0x38` | `void (*sing)(chorister_t *)` |
| `+0x40` | `char *transcript` |
| `+0x48` | `size_t transcript_len` |
| `+0x50` | `int active` |

`retire` does `free(transcript); free(c); c->active = 0`. `restore` only
requires a non-NULL slot and `active==0`, then sets `active=1`. Recite, roster,
and perform all follow the dangling pointer. Full RELRO, canary, NX, PIE, CET;
`sing` must be a function entry (`endbr64`) because remote IBT is enforced.
`system` is legal; a mid-function one-gadget is not.

### Step 2: Leak

Recruit seat 0 with a 0x500 transcript (unsorted on free), plus two small
partners. Retire 0, restore 0, recite 0. The first 8 bytes are unsorted `fd` =
`libc+0x21ace0` on the bundled libc.

### Step 3: Overlap

A 0x58 transcript is the same 0x60 tcache class as `chorister_t`.

1. Recruit a 0x58 pad whose payload sets `active=0` (and `sing=puts`) so the
   dangling leak seat is skipped under IBT.
2. Retire seats 1 and 2 (two 0x60 structs into tcache).
3. Recruit a 0x58 win transcript:

```
name        = "/bin/sh"
sing        = system
active      = 1
```

tcache LIFO places that payload on seat 2. Final Performance calls
`system("/bin/sh")`.

Remote stdout is fully buffered (`setvbuf(..., _IOFBF, 0x1000)`). Local
pwntools uses a PTY so `id` appears immediately; on the socket, send `cat
flag.txt` and wait. Do not call a leftover seat whose `sing` is not an IBT
entry — that closes the connection before seat 2 runs.

### Step 4: Reproduce

```text
cd agent_workspace
python3 solve.py              # local
python3 solve.py REMOTE       # instance
```

## Flag

`csaw{c0pper_c01ls_s1ng_wh4t_y0u_wr1te}`

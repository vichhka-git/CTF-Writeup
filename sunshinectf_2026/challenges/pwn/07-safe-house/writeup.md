# Sunshine CTF 2026 Writeup: Safe House

- **Category:** Pwn
- **ID:** 7
- **Points / Solves:** 488 pts / 99 solves
- **Connection:** `nc chal.sunshinectf.games 26007`
- **Flag:** `sun{n3gat1ve_h4ndl3s_0pen_s3cret_d00rs}`

---

## Challenge

> The safe house processes reports and files notes for the field. Get past the front desk and into the vault.
> 
> Files:
> * [service](https://sunshinectf.games/files/4a5ed2/service)

---

## Summary

A signed record index with an upper bound but no lower bound: index `-4` reaches the system table
entry holding the already-open `flag.txt` descriptor.

## Solution

No PIE, no canary. The `SUBMIT` handler reads the low byte of a requested size into a 64-byte stack
buffer, with saved RIP at offset 72, so a short return sequence reaches the existing frame builder
and response handler — no libc or PIE leak is required.

The forked child keeps four type-2 system entries immediately before its 16 public records. Its
`RELAY` op 3 reads a **signed** dword index and checks only `index <= 15`; there is no lower bound.
The public table begins at `0x4060b0`, so index `-4` maps to the first system entry at `0x405080`,
whose descriptor is the already-open `flag.txt`. That entry is read with `pread(fd, ..., 0x400, 0)`.

The exploit writes `fc ff ff ff` (signed `-4`) into note slot 0, uses `SUBMIT 232` to return through
the fixed address `0x401d50` with `(op=3, note0, len=4)`, then re-enters `RELAY` with op 4 to collect
and print the pending response.

## Ruled Out

- A libc leak: not needed — no PIE plus no canary means the return slot is reachable with nothing
  leaked and every gadget is at a static address.
- This target ships **no** libc or loader, so any locally `pwninit`-patched copy diverges from the
  remote; the unpatched binary was verified by SHA-256 before use.

## Files

- `files/service`

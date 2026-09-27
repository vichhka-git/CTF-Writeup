# Sunshine CTF 2026 Writeup: Homemaker

- **Category:** Pwn
- **ID:** 14
- **Points / Solves:** 484 pts / 116 solves
- **Connection:** `nc sunshinectf.games 26008`
- **Flag:** `sun{the_future_is_now_today_well_wait_how_are_you_reading_this}`

---

## Challenge

> # A SERVANT IN EVERY HOME, BY 1975!
> APEX ATOMIC HOUSEHOLD INDUSTRIES, INC IS PROUD TO ANNOUNCE THE MODEL 7 "HOMEMAKER" DOMESTIC AUTOMATON
> 
> POWERED THROUGH USE OF PUNCH CARDS, THE MODEL 7 IS EQUIPPED WITH THOUSANDS OF BYTES OF MEMORY!
> 
> THE FUTURE IS HERE, NOW!
> 
> Files:
> *[homemaker](https://sunshinectf.games/files/41a9ef/homemaker)

---

## Summary

A punch-card protocol whose length check is off by one — and the byte that overflows is the
low byte of the bound that governs it.

## Solution

The service speaks a framed binary protocol: `1b 5b | len(BE16) | payload | crc8 | 1b 5c`, with a
CRC-8 (poly `0x2F`) over the payload. Opcode 1 authenticates (key `0x1337C35F`, big-endian), 2 writes
the card, 3 reads it back, 4 exits, 5 calls `system("/bin/echo -n ''")`.

**The bug.** The write handler bounds-checks the copy as:

```c
if ((uint16_t)(len - 1) > *(uint16_t *)(buf + 256)) return -30;
for (i = 0; i <= (uint16_t)(len - 1); ++i) buf[i] = payload[1 + i];
```

`len - 1 <= capacity` permits `len = capacity + 1`, so 257 bytes go into a 256-byte buffer — and
`buf[256]` **is the low byte of the capacity field**. One overflow enlarges its own bound.

**Turning that into a leak.** The read handler dumps `capacity` bytes from the buffer. With capacity
grown to `0x01FF`, that read now reaches well past the buffer:

| offset from buf | contents |
| --- | --- |
| 256 | capacity (`v8`) |
| 264 | stack canary |
| 272 | saved rbp |
| 280 | saved RIP -> PIE base |

**The chain.** Authenticate; write 257 bytes so the CRC byte lands on `buf[256]` as `0xFF` (the CRC is
forced by sweeping one filler byte, since CRC-8 is a bijection in any single byte); read back to
recover the canary and PIE base; write again past the canary with a ROP chain.

No libc is needed. `rdi` points at `/bin/sh` carried in the **global frame buffer** at a fixed PIE
offset, so the chain is `pop rdi ; ret` -> `PIE+0x4865` -> `system@plt`. One subtlety: the trigger
frame overwrites that global buffer, so the `/bin/sh` string has to ride in the *trigger* frame
itself — opcode 4 ignores its payload, so the string travels for free.

Arriving at `system` via `ret` leaves `rsp` 16-byte aligned where the ABI wants 8, so an extra bare
`ret` gadget is spliced in before it to avoid faulting in glibc's `movaps`.

## Ruled Out

- Shellcode on the stack: NX is enabled.
- A libc leak: unnecessary once `/bin/sh` is placed at a known PIE offset in `.bss`.

## Files

- `files/homemaker`

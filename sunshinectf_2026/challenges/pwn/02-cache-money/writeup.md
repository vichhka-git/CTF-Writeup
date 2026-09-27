# Sunshine CTF 2026 Writeup: Cache Money

- **Category:** Pwn
- **ID:** 2
- **Points / Solves:** 483 pts / 120 solves
- **Connection:** `nc chal.sunshinectf.games 26004`
- **Flag:** `sun{s4fe_l1nk1ng_w0nt_s4ve_y0ur_tc4che}`

---

## Challenge

> The arcade's credit manager tracks every wallet in the house. The books haven't been audited in years, so help yourself.
> 
> Files:
> * [cache_money](https://sunshinectf.games/files/4995ef/cache_money)
> * [libc.so.6](https://sunshinectf.games/files/4995ef/libc.so.6)
> * [ld-linux-x86-64.so.2](https://sunshinectf.games/files/4995ef/ld-linux-x86-64.so.2)

---

## Summary

`transfer()` frees the source wallet's ledger and then hands that same pointer to the destination
— a use-after-free with full read and write over a chunk sitting in tcache.

## Solution

A 16-slot heap note manager (glibc 2.39, safe-linking). The bug is in transfer:

```c
free(src->ledger);
dst->ledger = src->ledger;     /* dangling */
dst->size   = src->size;
```

Deposit is `read(0, ledger, size)` and withdraw is `write(1, ledger, size)`, so the destination gets
a full read **and** write over a freed chunk.

**Leaking without hardcoded offsets.** Safe-linking stores `(chunk >> 12) ^ next`. Read the chunk
while it is the *only* entry in its bin — `next` is NULL, so the stored word is exactly `chunk >> 12`,
which is the shift needed for any chunk in that page. No heap offsets have to be guessed.

**Ordering matters.** A `put` issued after a `delete` simply pops the chunk that delete just freed,
so an interleaved loop only ever recycles one chunk and tcache never reaches a count of 2. Both
chunks must be allocated *before* either is freed.

**Where to land.** `open()` memsets every new ledger, so poisoning a chunk onto `.got.plt` zeroes it
and the next `printf` jumps to 0. Instead the poisoned chunk lands on the **wallet pointer array**
in `.bss`, where zeroing costs nothing. The deposit that follows rewrites that array so slot 0 points
at a fake wallet struct built *inside the same write* — self-referential, so no heap address is
needed — whose `ledger` field is `.got.plt`. That gives a clean read (libc leak) and then a clean
write, with no memset on either path. Finally `strtol@got` becomes `system`, and `main` dispatches
on `strtol(menu_buf)` with `rdi` already pointing at it.

## Ruled Out

- The glibc 2.34+ tcache `key` is a **random per-process value**, not `&tcache_perthread_struct`;
  it cross-checks nothing. Plenty of writeups still describe it the old way.

## Files

- `files/cache_money`
- `files/ld-linux-x86-64.so.2`
- `files/libc.so.6`

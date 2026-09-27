# Sunshine CTF 2026 Writeup: Code Breaker

- **Category:** Pwn
- **ID:** 3
- **Points / Solves:** 487 pts / 104 solves
- **Connection:** `nc chal.sunshinectf.games 26005`
- **Flag:** `sun{cr4ck_tHe_ciPh3r_fr33_thE_heaP}`

---

## Challenge

> CodeBreaker: enterprise-grade encrypted key-value storage. All traffic is encrypted with our proprietary cipher. Your data has never been safer.
> 
> Files:
> * [code_breaker](https://sunshinectf.games/files/734617/code_breaker)
> * [libc.so.6](https://sunshinectf.games/files/734617/libc.so.6)
> * [ld-linux-x86-64.so.2](https://sunshinectf.games/files/734617/ld-linux-x86-64.so.2)

---

## Summary

The "proprietary cipher" is a stateful XOR keystream whose key material is derived from a
**plaintext** nonce handshake, and `delete()` frees unconditionally while only clearing the slot
when the refcount was 1.

## Solution

**The cipher.** `buf[i] ^= S[(M[i & 15] + C + i) & 0xFF]`, then `C += len`.

- `S` — a 256-byte permutation at `0x2040` in `.rodata`, static and extractable from the file.
- `M` — 16 bytes derived during the handshake from `server_nonce || client_nonce`, both of which
  travel **in the clear**, so `M` is fully computable by the client.
- `C` — two counters, `0x42C0` for receive and `0x42C4` for send, each cumulative over message length.

Modelling `C` per-message decrypts message #1 perfectly and garbles every later one — which looks
exactly like a broken exploit rather than a wrong cipher model.

**The bug.**

```c
free(slot->ptr);
if ((slot->refs)-- == 1) { slot->size = 0; slot->ptr = 0; }
```

`DUP` (opcode 0x14) aliases one chunk into a second slot and bumps the source refcount to 2, so
`DELETE` on the source frees the chunk and leaves **both** pointers live: use-after-free with read
(`GET`) and write (`UPDATE`) over a tcache chunk.

**No libc leak is needed.** `main()` stores `&sub_1390` in a function pointer at `0x40C0`, command
`0x16` dumps that region straight back (PIE leak), and command `0x15` **calls** that pointer with our
own NUL-terminated string as its argument. `system` is imported. So tcache-poisoning a chunk onto
`0x40C0` and writing `system@plt` there turns `0x15` into `system(our_string)` — and `PUT` does
`malloc` then `memcpy` of exactly our bytes, with no memset to fight.

## Ruled Out

- `convert_from`-style text handling and libc leaking: unnecessary, `system@plt` plus the PIE leak
  is sufficient.
- Interleaved allocate/free ordering: as in Cache Money, both chunks must exist before either is freed.

## Files

- `files/code_breaker`
- `files/ld-linux-x86-64.so.2`
- `files/libc.so.6`

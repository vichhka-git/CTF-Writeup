# Sunshine CTF 2026 Writeup: Mad Libs

- **Category:** Pwn
- **ID:** 4
- **Points / Solves:** 482 pts / 123 solves
- **Connection:** `nc chal.sunshinectf.games 26001`
- **Flag:** `sun{f1ll_iN_th3_g0T_eNtry}`

---

## Challenge

> Fill in the blanks! Our Mad Libs game prints back whatever you type. It's just a simple word game... right?
> 
> Files:
> * [mad_libs](https://sunshinectf.games/files/fbf35f/mad_libs)
> * [libc.so.6](https://sunshinectf.games/files/fbf35f/libc.so.6)
> * [ld-linux-x86-64.so.2](https://sunshinectf.games/files/fbf35f/ld-linux-x86-64.so.2)

---

## Summary

`printf(user_buffer)` with the buffer sitting exactly on positional argument 8.

## Solution

PIE, canary and Partial RELRO. The canary is irrelevant (the stack frame is never touched) and
Partial RELRO leaves `.got.plt` writable, so one `%n` write is the whole exploit. Eight rounds of
input are available.

The buffer lands exactly on positional arg 8, making it its own pointer array.

**The trap that cost the most time:** arguments 1-5 are `rsi/rdx/rcx/r8/r9` at call time and hold
leftovers from the preceding `fgets`, so they shift with input length. `%3$p` *looked* like a stable
libc pointer across one run and was not. Both anchors had to be moved onto saved return addresses on
the stack and verified identical across three independent runs before being trusted:

- `arg43` = `__libc_start_call_main+0x7a` -> libc base
- `arg47` = a code offset in the binary -> PIE base

Then only the **low 3 bytes** of `printf@got` need replacing, because bytes 3-7 are shared between
`printf` and `system` in the same libc — two `%n` writes instead of six. `printf`'s GOT slot is read
at call time, so the call performing the write completes normally and the *next* `printf(buffer)` is
already `system(buffer)`.

## Ruled Out

- Anchors in argument slots 1-5: register leftovers, not stable. Verify a leaked anchor across
  independent runs before building on it.

## Files

- `files/ld-linux-x86-64.so.2`
- `files/libc.so.6`
- `files/mad_libs`

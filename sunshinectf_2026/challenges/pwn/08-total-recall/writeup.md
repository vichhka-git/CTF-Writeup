# Sunshine CTF 2026 Writeup: Total Recall

- **Category:** Pwn
- **ID:** 8
- **Points / Solves:** 467 pts / 165 solves
- **Connection:** `nc chal.sunshinectf.games 26003`
- **Flag:** `sun{r3caLl_ev3Ry_reGist3r_sR0p}`

---

## Challenge

> Can you recall how to get out of this one?
> 
> Files:
> * [total_recall](https://sunshinectf.games/files/54cf6a/total_recall)

---

## Summary

A 108-byte static ELF with no libc and no canary: leak a stack pointer, overflow, and SROP into
`execve`.

## Solution

The binary is minimal, statically linked, no canary, fixed base `0x400000`. The first function
leaks a stack pointer via `sys_write` and reads 24 bytes; the second reads `0x400` bytes into a
buffer at `rsp-0x80`, giving the overflow.

Overflow the return address back into the second function, stage a `SigreturnFrame` on the stack
describing `execve("/bin/sh", 0, 0)`, then supply **exactly 15 bytes** to the following `read`
syscall so that `RAX` is left as 15 — `SYS_rt_sigreturn` — which triggers the sigreturn into
`execve`.

## Ruled Out

- Stack shellcode: the kernel maps the stack non-executable (`rw-p`) even with no `PT_GNU_STACK`.
- Conventional ROP: only 108 bytes of code, so there are effectively no gadgets.

## Files

- `files/total_recall`

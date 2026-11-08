# relic

**Category:** Pwn · **Points:** 450 · **Flag:** `CSCTF{xsHTXl5sNa8OYiYJmtyKj1Fb}`

## What the handout gives you

A tarball with a deliberately old target and the runtime it was built against:

- `relic` — 16 KB x86-64 ELF, non-PIE, no stack canary, full RELRO (the build line in the source is `-O0 -fno-stack-protector -no-pie -Wl,-z,relro,-z,now`).
- `relic.c` — the source, including a comment that it was built on Ubuntu 20.04 so the real `__libc_csu_init` is linked in.
- `libc.so.6` and `ld-linux-x86-64.so.2` — Ubuntu 20.04 glibc 2.31, the exact runtime.

## Walkthrough

1. **Read `vault()`.** It declares `char buf[0x40]` and calls `read(0, buf, 0x120)`, then writes a newline and returns. The saved return address sits 0x48 bytes into the input. A `visited` counter allows one call, and that single `read` is the only input the program takes.

2. **Check the gadgets.** The binary is non-PIE, so `objdump -d relic` gives fixed addresses. `__libc_csu_init` holds the classic pair: `pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret` at 0x4012da, and `mov rdx,r14; mov rsi,r13; mov edi,r12d; call [r15+rbx*8]; add rbx,1; cmp rbp,rbx; jne ...` at 0x4012c0. With rbx=0 and rbp=1 the loop calls one function pointer and then falls into the epilogue, which pops six values and returns. `leave; ret` is at 0x401218.

3. **Leak and reload from one read.** One read cannot both leak an address and start a shell, so it does two jobs. The writable page at 0x404000-0x405000 gives the second payload a destination. The first chain calls `write(1, 0x403fd8, 8)` against the `write` GOT entry, then `read(0, 0x404800, 0x400)`, then pivots with `leave; ret`.

4. **Lay out stage 1 (0x108 bytes).**

- 0x40 filler
- 8 bytes of saved rbp
- 0x4012da, then rbx=0, rbp=1, r12=1 (edi), r13=0x403fd8 (rsi), r14=8 (rdx), r15=0x403fd8
- 0x4012c0, then 8 bytes that `add rsp,8` discards
- rbx=0, rbp=1, r12=0 (edi), r13=0x404800 (rsi), r14=0x400 (rdx), r15=0x403fe8
- 0x4012c0, then 8 discarded bytes
- rbx=0, rbp=0x404808, r12=r13=r14=r15=0
- 0x401218

The second call block is reached without another pop gadget: the first call's epilogue pops those six values and its `ret` lands on 0x4012c0 again.

5. **Receive the leak.** `vault()` writes its newline before it returns, so the client reads 9 bytes: 0x0a followed by the 8-byte `write` pointer. Libc base is that pointer minus 0x10e280, the `write` offset in the bundled libc (`readelf -s libc.so.6` lists `write` and `system`; `strings -t x libc.so.6 | grep /bin/sh` gives the string offset 0x1b45bd).

6. **Send stage 2.** It lands at 0x404800, the new rbp goes at 0x404808, and the chain starts at 0x404810: `pop rdi; ret` (libc+0x23b6a), a pointer to `/bin/sh` (libc+0x1b45bd), `ret` (libc+0x23b6b), `ret` again, then `system` (libc+0x52290). The two returns are load-bearing. `leave; ret` enters the chain with rsp at 0x404818, so a single `ret` reaches `system` with rsp ≡ 0 mod 16, while the ABI expects ≡ 8 at the first instruction of a function. One `ret` segfaulted on the remote instance; two worked.

7. **Use the shell.** `system("/bin/sh")` runs with the socket as stdin. `cat /flag` prints the flag.

## Answer

The shell prints `CSCTF{xsHTXl5sNa8OYiYJmtyKj1Fb}` from `/flag` on the instance.

## Notes

- ret2dlresolve looks attractive for a one-read, no-leak binary, but it cannot work here. `-z now` means the lazy resolver is never set up, so `GOT[1]` and `GOT[2]` stay zero. Dumping 8 bytes at 0x403fb8 shows both zero, and a forged relocation jumps to address 0.
- Full RELRO does not block the leak: the GOT is read-only, not unreadable.
- All libc offsets belong to the bundled 2.31 libc. A distribution libc will not match.
- Alignment differed between local emulation and the remote instance. Treat the second `ret` as required, not optional.

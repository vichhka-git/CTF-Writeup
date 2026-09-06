# baiby-pwn - Writeup

* **Category:** PWN
* **Points:** 100
* **Solves:** 3
* **Author:** Flagyard
* **Event:** BlackHat MEA Qualification CTF 2026

---

## Vulnerability & Mechanism

`arr[i] = v` has no bounds check. `getval()` reads 7 bytes then `atol`, so menu writes are 7-digit decimals. Partial RELRO + non-PIE places GOT and the stdout copy reloc just before `arr`, so negative indices smash GOT with binary addresses.

Landlock only allows executing `/app/baiby-pwn` and `ld.so`. There is no shell: the flag is `/flag-<md5(contents)>.txt`.

---

## Exploitation Path

1. **Control Flow Hijack & Libc Leak:**
   Hijack `setbuf@GOT` to `0x4011e2` (`mov rsi, rax; xor edi, edi; call read`) and `memset@GOT` to `0x401231` (reload stdout, call setbuf). Cmd 2 becomes `read(0, stdout FILE, 0x40)`. A fake `_IO_FILE` with `write_base = read@GOT` plus restoring the setbuf PLT stub makes the next `setbuf(stdout, 0)` flush 8 bytes of libc.

2. **Stack Pivot Preparation:**
   The same trampoline with `stdout_copy = dest` is a 64-byte raw write. Plant a ROP at `arr` (binary-safe; `gets` would stop on `0x0a` in ASLR addresses).

3. **Stack Pivot:**
   Cmd 2 calls `xchg eax, esp; ret` (libc `0x47cdf`). Non-PIE `arr = 0x404080` fits in 32-bit EAX, so this pivots onto the planted chain.

4. **Bypassing Seccomp / Landlock:**
   `pwn.red/jail` seccomp blocks `SYS_open`. Regular files still open with `openat(AT_FDCWD, path, rdx=0x40)` because leftover `rdx` from cmd 2 is `O_CREAT`, which is harmless on an existing file. Directories fail `EISDIR`.

5. **Flag Discovery & ORW:**
   `libc.open(path, 0)` opens `/` with flags 0 but zeros `rdx`. Restore `rdx = 0x40` with `pop rbp; pop rdx; leave; ret` (`0x981ad`), then `getdents64` + `write`. Parse `flag-<md5>.txt` and ORW it on a second connection.

---

## Dead Ends & Constraints

- Exit-time FSOP on the binary's stdout copy reloc: libc flush uses `_IO_list_all`.
- `dup2(3, 0)` then another menu command: `getval` consumes the flag file and `atol` returns 0, so the process exits.
- Raw `SYS_open` / `gets()` ROP: seccomp and embedded newlines.

---

## Key Takeaway

A 7-digit write is enough to turn cmd 2 into `read`/`setbuf` gadgets. After a libc leak, pivot with `xchg eax, esp` (the reason the binary is non-PIE) and treat leftover `rdx=0x40` as a feature: file `openat` flags, `read`/`write` count, and `getdents` size — unless a libc function clobbers it.

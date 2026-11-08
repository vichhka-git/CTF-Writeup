# Sigil

**Category:** Pwn · **Points:** 540 · **Flag:** `CSCTF{kNUYRe4o9H9DutmSt2UxPrHx}`

## What the handout gives you

The handout contains a minimal standalone Linux executable without shared library dependencies.

- `sigil.tar.gz` — an archive holding the challenge binary.
- `sigil` — a 64-bit statically linked x86-64 ELF executable without standard C library runtime objects.

## Walkthrough

1. **Inspect binary protections and structure.** Running `checksec` on `sigil` shows no stack canary, no position-independent execution (base address `0x400000`), and no NX disablement. The binary contains fewer than 100 machine instructions written directly in assembly.

2. **Map the execution flow.** The program starts at `_start` (`0x401000`), sets up file descriptors, and invokes `listen()` at `0x401030`. `listen()` issues a `read` syscall (`rax = 0`, `rdi = 0`) targeting a stack buffer at `rsp`, reading up to `0x400` bytes. Because the allocation on the stack is smaller than the requested length, the return address is directly overwritten.

3. **Identify SROP primitive availability.** Searching for gadgets reveals no `pop rdi` or `pop rsi` instructions. However, the binary contains:
   - A standalone `syscall` instruction at `0x401024`.
   - A loop re-entering `listen()` at `0x401030`.
   - Writable unrandomized BSS memory at `0x404000`.
   In x86-64 Linux, system call 15 (`0x0f`) is `SYS_rt_sigreturn`. When `syscall` executes with `rax = 15`, the kernel reads a `sigcontext` structure off the stack and copies all register states directly into CPU registers.

4. **Control RAX using `read()` return value.** A `read` syscall sets `rax` equal to the number of bytes received. By directing execution to a small `read` call and sending exactly 15 bytes over the socket, `rax` becomes 15 immediately prior to executing the `syscall` gadget at `0x401024`.

5. **Stage 1: Read second-stage payload into BSS.** Construct a forged `sigcontext` frame on the stack:
   - `rdi = 0` (stdin)
   - `rsi = 0x404000` (BSS)
   - `rdx = 0x500` (length)
   - `rax = 0` (`SYS_read`)
   - `rip = 0x401024` (`syscall`)
   - `rsp = 0x404000` (pivot stack to BSS)
   Triggering `rt_sigreturn` forces the kernel to restore these registers and execute `read(0, 0x404000, 0x500)`.

6. **Stage 2: Execute `execve("/bin/sh")`.** Transmit the second-stage payload into BSS. The payload writes the string `"/bin/sh\x00"` at `0x404000` followed by a second signal frame configured for `execve`:
   - `rdi = 0x404000` (pointer to `"/bin/sh"`)
   - `rsi = 0` (`NULL`)
   - `rdx = 0` (`NULL`)
   - `rax = 59` (`SYS_execve`)
   - `rip = 0x401024` (`syscall`)
   Send a 15-byte string to set `rax = 15` and trigger the `sigreturn` syscall. The kernel restores the registers and invokes `execve("/bin/sh", NULL, NULL)`.

7. **Capture the flag.** Read the flag file from the spawned shell session with `cat /flag`.

## Answer

Executing the shell payload retrieves the flag:

`CSCTF{kNUYRe4o9H9DutmSt2UxPrHx}`

## Notes

A 64-bit `sigcontext` structure expects specific flags and segment register values. In particular, setting `cs = 0x33` and ensuring valid alignment prevents kernel faults during the `sys_rt_sigreturn` transition.

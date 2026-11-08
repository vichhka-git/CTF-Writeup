# echo_chamber

**Category:** Pwn · **Points:** 540 · **Flag:** `CSCTF{F2uIkJBgw6OQchjVpSBVIxQn}`

## What the handout gives you

The handout contains a tarball with the challenge binary, source code, and dynamically linked loader and C library:

- `echo_chamber.tar.gz` (1,072,026 bytes)
- `echo_chamber` (16,456 bytes) — 64-bit ELF binary compiled with full protections (Full RELRO, Canary, NX, PIE).
- `echo_chamber.c` (1,007 bytes) — C source code of the echo service.
- `libc.so.6` (2,220,400 bytes) — target GNU C Library runtime.
- `ld-linux-x86-64.so.2` (240,936 bytes) — dynamic linker matching the bundled libc.

## Walkthrough

1. **Audit the source code.** The service executes in a loop inside `chamber()`. It allocates a stack buffer `char buf[0x50]` (80 bytes) and reads up to `0x70` (112 bytes) from standard input:

   ```c
   char buf[0x50];
   for (;;) {
       printf("> ");
       read(0, buf, 0x70);
       if (strncmp(buf, "bye", 3) == 0) break;
       printf("echo: %s\n", buf);
   }
   ```

   The read operation exceeds the buffer capacity by 32 bytes, allowing controlled stack overflow while the `%s` format specifier permits sequential memory leaks across null-byte boundaries.

2. **Leak the stack canary.** The compiler places the stack canary immediately after the 88-byte buffer alignment (`buf + 0x58`). The lowest byte of a standard Linux canary is always `0x00`. Sending exactly 89 non-null bytes overwrites this leading null byte. `printf("echo: %s\n", buf)` continues printing past the buffer, leaking the remaining 7 bytes of the active canary.

3. **Leak saved base pointer and code addresses.** Continuing the non-null fill:
   - Sending 96 bytes overwrites through the canary, leaking the saved frame pointer (RBP) to establish the stack layout.
   - Sending 104 bytes reaches the saved return address (pointing to `main + 38`), disclosing the binary's runtime PIE base address.

4. **Overcome the limited ROP payload space.** Exiting the loop requires sending a payload starting with `"bye"`. With `0x70` bytes total read capacity, only 8 bytes remain after overwriting the canary, saved RBP, and return address. To execute an arbitrary ROP chain, pivot the stack:
   - Overwrite saved RBP with the address of a known writable buffer in the binary's BSS segment.
   - Set the return address to a `leave; ret` gadget.
   - Upon loop exit, the `leave` instruction loads the pivoted BSS address into RSP, moving execution to a larger staged ROP chain.

5. **Disclose the libc base address.** In the first staged ROP chain on the pivoted stack, call `puts(puts@GOT)` followed by re-entering `chamber()`. The output leaks the runtime address of `puts()` in libc. Subtracting the symbol offset of `puts()` from the bundled `libc.so.6` calculates the base address of libc.

6. **Execute a shell.** With the libc base established, construct the final ROP sequence:
   - Load the address of the string `"/bin/sh"` into RDI using a `pop rdi; ret` gadget from libc.
   - Align the stack with an extra `ret` instruction to satisfy the 16-byte SSE alignment requirement.
   - Call `system()` in libc.
   
7. **Read the flag.** Interacting with the spawned shell, transmit `cat /flag` to print the secret token.

## Answer

Spawning `/bin/sh` and reading `/flag` outputs the flag:

`CSCTF{F2uIkJBgw6OQchjVpSBVIxQn}`

## Notes

The 32-byte overflow limit (`0x70 - 0x50`) is intentionally too small to fit both a register setup and a library call in a single frame. Pivoting the stack via saved RBP and `leave; ret` is necessary to stage the multistage ret2libc chain.

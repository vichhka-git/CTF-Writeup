# Forge

**Category:** Pwn · **Points:** 270 · **Flag:** `CSCTF{v47kUPx4j1ODEQewthDp88er}`

## What the handout gives you

The handout contains a networked heap management service along with its source code and dynamic library dependencies.

- `forge` — 64-bit ELF executable compiled with PIE, stack canary, and Full RELRO.
- `forge.c` — C source code implementing a note forge and temper service.
- `libc.so.6` — Ubuntu 18.04 glibc 2.27 shared library.
- `ld-linux-x86-64.so.2` — ELF dynamic linker matching the bundled libc.

## Walkthrough

1. **Audit the source code.** `forge.c` maintains an array of up to 16 notes. Each note has a heap data pointer and a size. The menu offers four operations: `forge` (allocates via `malloc`), `temper` (appends data), `inspect` (prints data with `puts`), and `melt` (frees memory via `free` and clears pointers).

2. **Identify the heap overflow in `temper()`.** When appending data to an existing note, `temper()` executes:
   ```c
   read_until_nl(p + strlen(p), notes[i].size);
   ```
   The read accepts `notes[i].size` bytes starting at offset `strlen(p)` instead of `size - strlen(p)`. If a note contains non-empty text, this logic writes up to `strlen(p)` bytes beyond the chunk's user data boundary into the metadata of the next chunk.

3. **Leak libc via the unsorted bin.** Allocate note 0 with size `0x500`, exceeding the `0x410` maximum tcache chunk threshold. Allocate note 1 (size `0x20`) as a wilderness boundary guard. Calling `melt` on note 0 places its chunk into the unsorted bin. Reallocating note 0 with size `0x500` and an empty string leaves the unsorted bin pointers intact. Inspecting note 0 leaks the `fd` pointer pointing to `main_arena + 96` (`0x3ebca0` in the bundled libc), exposing the libc base address.

4. **Poison the tcache freelist.** In glibc 2.27, tcache chunks lack double-free integrity checks and pointer obfuscation:
   - Allocate two small chunks of size `0x30` (notes 2 and 3).
   - Free note 2, then free note 3. The `0x40` tcache bin holds `note 3 -> note 2`.
   - Allocate a note that reclaims note 3.
   - Use the `temper()` overflow on the preceding adjacent chunk to overwrite note 3's forward pointer (`fd`) with `__free_hook - 8` (`libc_base + 0x3ed8e0`).

5. **Overwrite `__free_hook` with `system`.** Request two successive allocations of size `0x30`:
   - The first allocation returns the valid heap chunk from the head of the tcache bin.
   - The second allocation serves the forged pointer landing directly over `__free_hook`.
   - Writing `b"XXXXXXXX" + p64(system_addr)` places the address of `system` (`libc_base + 0x4f420`) into `__free_hook`.

6. **Trigger command execution.** Allocate a note containing the command string `cat flag* || cat /flag*`. Invoke `melt` on this note index. The binary calls `free(notes[idx].data)`, which resolves `__free_hook` and invokes `system("cat flag*")`.

## Answer

The command execution prints the flag from the server filesystem:

`CSCTF{v47kUPx4j1ODEQewthDp88er}`

## Notes

The glibc 2.27 runtime does not enforce `safe-linking` pointer mangling or chunk alignment checks on tcache entries. Pointing the poisoned `fd` directly to `__free_hook` or `__free_hook - 8` allows direct arbitrary write without needing House of Force size calculations.

# Ghost in the Historian

**Category:** Forensics · **Points:** 270 · **Flag:** `CSCTF{xorshift_ghost_in_the_historian_d2c19434a637}`

## What the handout gives you

The handout is a compressed ZIP archive containing a virtual disk and incident documentation:

- `ghost-in-the-historian.zip` (72,560 bytes, SHA-256 `5edaea927aa93db3286f771dd77c8c41e0c23c6eafa70ac2182da5bd9ac56ce9`).
- `evidence-flat.vmdk` (67,108,864 bytes) — uncompressed raw ext4 disk image from the compromised substation historian server.
- `evidence.vmdk` (321 bytes) — VMware disk descriptor file mapping the flat extent.
- `README_FOR_RESPONDERS.md` (952 bytes) — incident timeline documenting the adversary's intrusion and anti-forensics actions.
- `manifest.sha256` (256 bytes) — cryptographic integrity records for the disk image.

## Walkthrough

1. **Inspect directory contents on the ext4 filesystem.** Using Sleuth Kit file listing tools, survey the allocated directory hierarchy:
   ```bash
   fls -r -p evidence-flat.vmdk
   ```
   Under `/var/log/historian/`, three operational files have been encrypted in place and renamed: `grid_topology.cfg.enc`, `historian_cache.dat.enc`, and `node_status.json.enc`. The plaintext originals are absent.

2. **Locate the deleted encryptor binary.** The responder brief notes that the intruder ran an executable named `historian_enc` and deleted it before system shutdown. Searching unallocated block groups or parsing unallocated inodes locates an ELF header signature (`\x7fELF`) at block 2588 (byte offset 10,600,448). Carve the complete 14,472-byte binary from the raw image.

3. **Reverse engineer the encryption algorithm.** Open the carved binary in a disassembler. The binary iterates through target files using `scandir()` and encrypts file contents in 4-byte blocks by XORing them with a 32-bit pseudo-random keystream. The PRNG implementation matches Marsaglia's 32-bit Xorshift algorithm:
   - `x ^= (x << 13) & 0xFFFFFFFF`
   - `x ^= (x >> 17) & 0xFFFFFFFF`
   - `x ^= (x << 5) & 0xFFFFFFFF`

4. **Identify the seed derivation formula.** Disassembling the initialization routine reveals how the initial 32-bit seed is calculated:
   `seed = ((uint32_t)timestamp ^ (uint32_t)pid) * 0x9e3779b1` (evaluated modulo `2^{32}`).
   The state is initialized once at process startup and persists across all files processed in the scan loop.

5. **Recover the process identifier (PID).** Inspect the system logs on the disk image. Reading `/var/log/historian.log` reveals a service monitor entry that recorded the execution of the rogue binary with PID `2764964`.

6. **Recover the execution timestamp.** The encryptor calls `utime()` before exiting to reset file access and modification times on each `.enc` file. Running `istat evidence-flat.vmdk <inode>` on `grid_topology.cfg.enc` reveals an exact timestamp of `1790914385` (corresponding to 2026-10-02 04:13:05 UTC).

7. **Establish file processing order.** Because `scandir()` returns directory entries sorted alphabetically by `d_name`, the files are processed in strict alphabetical order:
   - `grid_topology.cfg.enc`
   - `historian_cache.dat.enc`
   - `node_status.json.enc`
   Because `grid_topology.cfg` is first, its keystream begins immediately at the initial seed without needing to account for bytes consumed by prior files.

8. **Generate the keystream and decrypt the configuration.** Calculate the initial seed:
   `(1790914385 ^ 2764964) * 0x9e3779b1 = 1788185849 * 0x9e3779b1 mod 2^32`.
   Advance the Xorshift32 PRNG to generate 4-byte keystream words, then XOR the keystream against `grid_topology.cfg.enc`. The decrypted text contains substation parameters and the embedded token.

## Answer

Decryption of `grid_topology.cfg.enc` restores the complete configuration entry containing the flag:

`CSCTF{xorshift_ghost_in_the_historian_d2c19434a637}`

## Notes

The PRNG state does not reset between files. If a reader attempts to decrypt `node_status.json.enc`, they must first cycle the generator through all bytes of `grid_topology.cfg` and `historian_cache.dat`. However, recovering the `SAFETY_INTERLOCK_TOKEN` only requires `grid_topology.cfg`, which starts at the very beginning of the keystream.

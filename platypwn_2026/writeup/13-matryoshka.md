# Matryoshka (rev)

**Flag:** `PP{th3r3_1s_4_b1n4ry_1n_my_b1n4ry?!}`

"A binary in my binary": the shipped executable unpacks a second, embedded
stage that is additionally password-protected.

## Steps

1. Run `strings`/`binwalk` on the shipped binary. There is an embedded
   stage-2 blob (a second ELF/packed image) plus a stub that decrypts it with
   a **repeated-key XOR**.

2. **Recover the password from CRC32.** The stage-2 header carries four
   32-bit CRC32 checksums for four 8-character chunks of the password.

3. Brute-force each chunk independently against its CRC32 (8 printable
   characters is ~2^40 naive, but a meet-in-the-middle or a crc32 "combine"
   trick makes it minutes: split the 8 characters 4+4 and combine
   `crc32(left) -> crc32(left||right)` tables).

4. XOR-decrypt the stage-2 blob with the recovered password (repeated over
   the length) and dump the ELF.

5. Run the stage-2 ELF — it prints the flag (or contains it as a plaintext
   resource after the unpacking).

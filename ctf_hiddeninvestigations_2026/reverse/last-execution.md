# Last Execution

Reverse, 56 points, 424 solves (author Hidden Investigations). The handout is a persisted
core image for a fictional processor called EXE-9, complete with its own instruction set
and a manual stored inside the image. Reading the manual is not enough: two of its rules
are wrong, and the telemetry record shipped with the image is a near miss. The flag is
sealed with a 256-bit block cipher keyed by the final register state.

## What you are given

`last-execution.zip` expands to `last_execution.img`, 8,650,752 bytes, magic `EXE9CORE`.
There is no live service and no login material.

The local submission log does not contain a gate transcript for this one. It holds the
pre-gate portal record, plus a later attempt that came back 409 "already submitted", so
the recorded solve is the portal one.

## Reproduction

1. Parse the header. Every field is big-endian: version 0x0901, 24 segments, EXEC_SEED
   0x9e3779b9f00dcafe, TABLE_SEED 0x0badc0ffee0ddf00d, ENTRY 1, MANUAL 10, image size
   8650752, header CRC32 0xf0b01a7f. The segment table starts at 0x100, and every segment
   CRC32 matches, so the image is intact before emulation starts.

   ```
   1 EXEC_MAIN   2 EXEC_FOLD_A   3 EXEC_FOLD_B   5 EXEC_LIMIT
   4 EXEC_FINAL  6 EXEC_SELFTEST 10 PRIMER       11 DLOOK
   12 DSEED     20 WILL_SEAL    30 TELEMETRY    31 SYMBOLS
   50 REV_NOTES 51 ARTIFACTS    52-55 FILLER_0 to FILLER_3
   ```

2. Read segment 10, the PRIMER. It documents the header layout, the page rotation chain,
   the instruction encoding, the rotating dispatch table, HALT chaining, table row
   rotation and the SEAL-256 seal format. It also prints two encode-time traces (page
   rotations for EXEC_MAIN, row rotations for DSEED) and a self-test commitment.

3. Build the emulator and check it against the self-test. Execute segment 6 standalone
   from pc 0 with cleared registers, then hash `be64(R1) || be64(R2) || be64(R3) || be64(R4)`
   with SHA-256. It has to equal
   `0b6d8d4770eac443de6b9b73340a4a262117d9da42e6ced9411ebda286bbbcf2`.

4. Do not trust the PRIMER unconditionally. Three rules had to be corrected before the
   commitment matched:

   ```
   dispatch:   idx = (op_byte + (pc >> 3) + AUX) mod 256    (PRIMER says pc >> 4)
   table rows: rr[i] = (rr[i-1]*17 + first_byte(row i-1) + i*13) mod 64   (PRIMER says i*11)
   seal maths: key schedule and folds use mod 2^64          (PRIMER implies 2^64 - 1)
   ```

   Page rotations are only printed for the first few pages, so the rest are recovered by
   scoring ROL64 on each page for the fraction of words that decode to in-table opcodes.
   The printed ROT[0..2] for EXEC_MAIN are the check on that scoring.

5. Run the chain. It is 1, 2, 3, 5, 4, 5, 4, END, that is EXEC_MAIN, EXEC_FOLD_A,
   EXEC_FOLD_B, EXEC_LIMIT, EXEC_FINAL, EXEC_LIMIT again, EXEC_FINAL again, then a
   terminating HALT. EXEC_FINAL counts its passes in a mailbox at 0x2038 and patches the
   low word of R1 so that the same HALT links onward on the first pass and stops on the
   second.

6. Fast-forward EXEC_LIMIT correctly. It runs N = 0x123456789abc = 20015998343868
   iterations of a loop whose state has period 786432, so 25,451,658 full periods plus
   39,612 iterations. The loop adds into the register that arrives in R8, so the shortcut
   has to carry it in: `R8_out = R8_in + q*period_sum + remainder_sum mod 2^64`. The two
   incoming values are 0x67481e8ae8dbbdcd for the first pass and 0x9b5e403149ed01e8 for
   the second. Dropping R8_in changes the whole second pass and the seal never opens.

7. Read the final state at the terminating HALT, which is at pc 0xd30 with R15 =
   0x5354414c:

   ```
   R1 = 0x30677df2a112fffb    R2 = 0xff975fd2b1f15576
   R3 = 0xabec2195f731c083    R4 = 0x9c3fb793eed6da86
   ```

   The TELEMETRY segment is not this state. It claims the final register file with R5 and
   R6 zero, which a real run cannot produce because EXEC_FINAL leaves R5 = 2 and
   R6 = 0x2038, and its R2 differs from the real one by 0x1000. The PRIMER appendix says
   the console record stands if the two disagree; here it does not.

8. Derive the key from the state.

   ```
   key = SHA256("LASTEXEC" || be64(R1) || be64(R2) || be64(R3) || be64(R4) || "LASTEXEC")
       = ac35ec6ed245d7238d9784ae097766613649315beb12b8ba9836dda56ccd54a3
   ```

9. Open WILL_SEAL. It is segment 20, at file offset 0x462b2, size 0x50: 16 shift bytes
   followed by four 16-byte blocks. All sixteen shifts are 0x5d, so with L = 4 each column
   moves by one row. Undo the column rotation with
   `ct[(r + shift[c]) mod L][c] = stored[r][c]`, which gives the unrotated ciphertext

   ```
   5f38fa29601cdd37abbe947c0e7e95bda9010c128e8417385065942871b6aad05fb855b456848e915453f91d0e23029ed608d65bb2f89f63eef1918384cf59ae
   ```

10. Decrypt with SEAL-256. The S-box is built from logical rows 0 to 3 of DLOOK with a
    Fisher-Yates shuffle driven by those bytes; its first 16 bytes are
    `c2fbea4099463359c49da23ab87aa3e0`. The key schedule yields 17 round keys, starting at
    RK0 = `ceac3c32efcd8e3112f87713bd88947a` and ending at
    RK16 = `3a786a583ddc9beaff35f60c03a6709a`. Decrypt a block by XORing RK16, then for
    r = 15 down to 0 undo the permutation P, the inverse S-box and the key RK[r].

    The 64 plaintext bytes end in 14 bytes of 0x0e, which is valid PKCS#7 for a 16-byte
    block, and the 50 bytes before that are the flag.

11. Ignore the decoys. Appendix A of segment 50 REV_NOTES XORs with 0x37 to
    `hiCTF{f4k3_fl4g}`, and the SYMBOLS segment advertises `will_seal_key = 0xF11E00` and
    `fold_oracle = 0xDEAD00`, neither of which falls inside any segment in the table.

## Why it works

The image carries its own specification, and the specification is close enough to build a
working emulator and wrong enough that a literal implementation diverges in ways that look
like a broken cipher. Once the self-test commitment matches, the final register state is
determined, the seal key is a hash of that state, and the seal is ordinary symmetric
decryption. The two records that look authoritative, the telemetry dump and the notes
appendix, both reward the reader who replays the image instead of trusting them.

## Flag

```
hiCTF{3x3c_9_r3m3mb3rs_4ll_but_th3_l4st_h4lt_l13s}
```

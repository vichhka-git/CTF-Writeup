# ChronoGrind

ChronoGrind is a cryptography challenge worth 58 points (324 solves). A wearable device sealed a message behind a sequential-squaring time-lock puzzle and left behind a state file that describes itself. The only route to the key is to actually evaluate the puzzle.

## What you are given

`chronogrind.zip` unpacks to `chronogrind/state.dat` (1358 bytes) and `chronogrind/flag.enc` (68 bytes). No service, no source, no login material.

## Reproduction

1. Look at the header:

   ```
   43 47 44 31 4c 00 4d 40 ...
   ```

   Bytes 0 to 3 are the magic `CGD1`. Byte 4 is `0x4c` and byte 5 is `0x00`. A single nonzero byte sitting between a magic and structured data is a one-byte XOR key, and byte 5 is reserved padding. Applying that XOR from offset 6 onwards turns the rest of the file into a clean record stream.

2. Parse the records. Each is `tag:u8, length:u32le, value:length`:

   ```
   from pathlib import Path
   b = Path('extracted/chronogrind/state.dat').read_bytes()
   d = bytes(x ^ b[4] for x in b); p = 6
   while p < len(d):
       t = d[p]; z = int.from_bytes(d[p+1:p+5], 'little')
       print(hex(p), hex(t), z); p += 5 + z
   ```

   Nine records at absolute offsets 0x6, 0x17, 0x11f, 0x227, 0x236, 0x243, 0x268, 0x370, 0x534, with tags 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88. The last record ends at 0x54e, which is exactly the file length, so the parse is complete. Tag 0x01 and tag 0x55 are ASCII (`team=testrun` and `the anchor holds. keep grinding.`), tag 0x44 is eight bytes, and tag 0x77 is a long ASCII note.

3. Read the note in tag 0x77. It defines the whole scheme, quoted here as recorded:

   ```
   anchor = rec[11] (base241), seed = rec[22] (base241), cycles = rec[33] (decimal)
   chk = rec[44] = sha256('anchor:seed:cycles' as decimal, colon-separated)[:8]
   derivation: v = seed; repeat cycles times: v = v*v mod anchor
   k = sha256(v as 256-byte big-endian)
   CGFX: magic 'CGFX'(4) ver(1) nonce(12) tag(16) ct(rest)
   aead = chacha20-poly1305, key = k, nonce = nonce field
   ```

4. Decode the two big integers. Both records are base-241 big-endian digit strings, so the value is a Horner sum:

   ```
   v = 0
   for x in record: v = v * 241 + x
   ```

   Recorded sizes: the anchor is 2048 bits, the seed is 2045 bits, and `cycles` is the ASCII string `9000000000`.

5. Check the note against itself before trusting any of it. The checksum is defined as

   ```
   sha256(f"{anchor}:{seed}:{cycles}".encode())[:8]
   ```

   and must equal record 0x44. Both sides are `3afdd49ebe78a45a`, so the base-241 direction, the decimal rendering and the field roles are confirmed at once by one comparison. Repeating the decode little-endian gives `0364f806536a9203`, which does not match, so the byte order is settled by evidence rather than by assumption.

6. Try to avoid the work, and record why every route fails.
   - Fermat reduction of the exponent needs the anchor to be prime. It is not prime, so `2^cycles` cannot be reduced modulo `anchor - 1`.
   - Trial division found no prime factor below 200000, and a Brent rho run with a 55 second budget found nothing. A 2048-bit composite with no small factors will not fall to rho.
   - Record 0x66 decodes to a 259-byte integer smaller than the anchor and coprime to both the anchor and the seed. Testing `pow(a, q, anchor)` for `a` in 2, 3, 5, 7, 11 does not return 1, so it is not the group exponent.

   That leaves the nine billion squarings. The description says "no shortcuts, and no, your cores won't save you", and after those three checks the claim is supported rather than assumed.

7. Actually grind. The recorded implementation is one single-threaded loop over OpenSSL's Montgomery arithmetic:

   ```
   BN_MONT_CTX_set(mc, n, ctx);
   BN_to_montgomery(a, a, mc, ctx);
   for (i = 0; i < 9000000000ULL; i++) {
       BN_mod_mul_montgomery(b, a, a, mc, ctx);
       t = a; a = b; b = t;          /* swap, no copy */
   }
   BN_from_montgomery(a, a, mc, ctx);
   ```

   Progress was logged every 1e8 iterations. The log starts at `100000000 34s 338ns/it` and ends at `9000000000 3125s 347ns/it`, drifting between 338 and 352 ns per squaring for a total of 3125 seconds, about 52 minutes. The iteration count is fixed and public, which is what makes a time-lock puzzle cheap to check and expensive to open.

8. Serialize the result correctly. The final value is 2047 bits, but the note says 256 bytes, so pad on the left:

   ```
   k = SHA256(v.to_bytes(256, 'big'))
   ```

   Recorded key: `96156b5d6965bf3ba35616cd280de13b2f7ae6e3734772083b7faf686cdf6148`. Minimal-length or little-endian encodings of the same integer produce different keys and the AEAD tag rejects them, so this step is self-checking.

9. Open the container. `flag.enc` begins `4347465801`, that is magic `CGFX` and version 1, then `nonce = [5:17]`, `tag = [17:33]`, `ciphertext = [33:68]`. Run ChaCha20-Poly1305 with key `k` and that nonce, and verify the tag before reading the plaintext.

## Why it works

This is a time-lock puzzle in the original sense. The ciphertext depends on `v = seed^(2^cycles) mod anchor`. The exponent is astronomically large, and the only way to evaluate it faster than by repeated squaring is to reduce it modulo the multiplicative order of the group, which needs `phi(anchor)` or the factorisation of `anchor`. The generator chose a 2048-bit composite with no small factors, so that door is shut.

The construction is what makes the work serial: each squaring takes the previous result as input, so the chain cannot be split across cores and cannot be branched in parallel. "Your cores won't save you" is an accurate description of the algorithm rather than a taunt.

The only property that is not adversarial is the amount of work. The puzzle is sized so one desktop core finishes in under an hour, which is why the description says to bring a charger. Anything longer would have been unsolvable inside an event.

## What the local notes do not record

The purpose of records 0x66 and 0x88 is not established. Record 0x66 is a 259-byte integer whose role the notes call unproven after the order test above, and record 0x88 (21 bytes) is never explained. Neither is needed for the solve.

## Flag

```
hiCTF{n1c3_w0rk_n0w_t4k3_s0m3_r3$t}
```

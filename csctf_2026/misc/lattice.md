# lattice

**Category:** Misc · **Points:** 200 · **Flag:** `CSCTF{I1ViZne6tg12jpjFtHYT1iAR}`

## What the handout gives you

- `lattice.py` — the forward cipher: an 8-byte block scrambler with a generated S-box, 16 round keys, and one 48-byte ciphertext in `TARGET`.
- The brief: an audit service accepts the original passphrase once, and the source ships no decrypt routine.

## Walkthrough

1. **Read the round function.** `encrypt_block` runs 16 rounds over an 8-byte list. Even rounds add the round key bytewise mod 256; odd rounds XOR it. Each byte is then substituted through `SBOX`, the eight bytes are packed big-endian into a 64-bit word, and the word is rotated left by `(7*r + 11) % 63 + 1`. `encrypt` pads with PKCS#7 and processes every 8-byte block independently.

2. **Reproduce the tables.** `SBOX` is a Fisher-Yates permutation of 0..255 driven by a 32-bit LCG seeded with 0x1A2B3C4D, multiplier 0x19660D, increment 0x3C6EF35F. The 16 round keys are eight bytes each from the same generator seeded 0xCAFEB0BA. Both are deterministic, so calling the handout's own builders is enough; nothing is keyed by a secret.

3. **Invert one block.** Walk the rounds backwards from 15 to 0. Rotate right by the same per-round amount (it is always 1..63, never 0, so nothing is lost), apply the inverse S-box permutation, then undo the key: subtract on even rounds, XOR on odd rounds.

4. **Glue the blocks.** `TARGET` is 48 bytes, six independent blocks. Concatenating their decryptions gives 48 bytes whose final byte is 0x04, so four bytes of PKCS#7 padding are present and the passphrase is the first 44:
`unl0ck-th3-l4tt1ce-pre1mage-3f9a7c2e1b8d4a60`
Running that string back through the handout's `encrypt` reproduces `TARGET` byte for byte, which confirms the inversion before touching the service.

5. **Speak it once.** Connect to the instance given by the scoreboard, read the prompt, and send the passphrase followed by a newline. The vault answers with the flag.

## Answer

The vault returns `CSCTF{I1ViZne6tg12jpjFtHYT1iAR}`.

## Notes

- The source comment says the S-box is not AES and the LCG constants are not standard. Rebuilding either from textbook values produces a different permutation and garbage plaintext.
- Byte order matters. The rotation operates on `int.from_bytes(bytes(s), "big")`, so a little-endian implementation decrypts every block to noise.
- ECB means no chaining: a wrong block only ruins that block, and the padding byte is an immediate correctness check on the last one.
- The service compares the whole string once. Send the passphrase exactly as recovered, with no trailing whitespace beyond the newline.

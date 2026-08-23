# Bit Garden - Writeup

## Challenge Overview
- **Category:** Reverse Engineering
- **Target:** `bit-garden.exe` (x86-64 Windows PE binary, 18KB)
- **Description:** "The smallest rooms remember the loudest guests."
- **Flag Format:** `e0f{...}`

## Analysis & Reverse Engineering
1. **Input Format & Validation:**
   - The program reads an input line and validates format `e0f{<32 characters>}` (total 37 bytes).
   - Validates that all 32 payload characters are printable ASCII.

2. **Pre-processing (Initial Permutation & Unpacking):**
   - The 32 payload bytes are XORed with a SplitMix64-derived pseudorandom stream and placed in a 32-byte buffer using a stride permutation `idx = (5 + 13 * i) % 32`.
   - The 256 bits of this 32-byte buffer are unpacked into a 16x16 2D grid (`256` bytes, each 0 or 1) at bit-reversed index positions `grid[bit_reverse_8(bit_idx)] = bit_val`.

3. **Cipher Core (Margolus Neighborhood Block Cellular Automaton):**
   - An S-box of 16 nibbles is constructed by XORing `.mazeA` and `.mazeB` sections: `[6, 11, 0, 4, 13, 3, 15, 8, 1, 10, 2, 12, 5, 9, 14, 7]`.
   - 56 rounds of reversible block transformations are performed on the 16x16 grid:
     - In each round `r` (0..55), the grid is partitioned into 2x2 blocks (with block offset `(r & 1, r & 1)`).
     - Each 2x2 block's 4 bits `(b0, b1, b2, b3)` form a nibble `v`, which undergoes key XOR, 4-bit rotation, S-box substitution, inverse rotation, and second key XOR.
     - The grid is then cyclically translated by a 2D offset `(row_shift, col_shift)`.

4. **Output Verification:**
   - The final 16x16 grid bits are packed into 32 bytes and compared against a generated target ciphertext derived from constant array at `0x1400040e0`.

5. **Inversion / Solution:**
   - Because all components (2x2 S-box substitution, bit rotation, 2D toroidal translation, bit-reversal, and byte permutation/XOR) are strictly bijective, the entire transformation is inverted backwards to recover the unique flag.

## Flag
`e0f{b1ts_g0_brrr_1n_t1ny_2x2_b0x3s_x}`

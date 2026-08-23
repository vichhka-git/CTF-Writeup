# NaN Penguin Cipher - Writeup

## Challenge Overview
- **Category:** Reverse Engineering
- **Difficulty:** Hard
- **Target Binary:** 64-bit ELF executable `nan-penguin-cipher`
- **Flag Format:** `e0f{...}`

## Analysis

1. **Input Validation & Preprocessing in `main`:**
   - The program reads a 53-character string from stdin.
   - It checks that the flag begins with `e0f{` and ends with `}`.
   - It enforces printable ASCII on the 48-byte payload.
   - A PRNG based on SplitMix64 generates a permutation and a 48-byte keystream.
   - Each character of the 48-byte payload is XORed with the keystream and placed at its permuted position in a 48-byte buffer.
   - The 48 bytes are grouped into six 64-bit words: $W_0, W_1, W_2, W_3, W_4, W_5$.

2. **The Custom Block Cipher (`0x403800`):**
   - The key schedule verifies and unpacks NaN payload constants from `.rodata` and initializes round subkeys on the stack.
   - The cipher executes 18 rounds. Each round consists of three layers:
     - **Layer 1 (Word Substitution):** For each of the 6 words independently:
       - $W_i \leftarrow (W_i \oplus K1_i + K2_i) \cdot K3_i \pmod{2^{64}}$
       - Byte-wise Galois Field multiplication in $GF(2^8)$ using irreducible polynomial $x^8 + x^4 + x^3 + x + 1$ (0x11b) with $K4_i$ (or fallback 0x63 if 0).
       - Left rotation $W_i \leftarrow 	ext{ROL}(W_i, 	ext{shift1}_i)$.
     - **Layer 2 (Feistel Mixing):** 6 sequential unbalanced Feistel steps:
       - For $r_{11} \in [1..6]$:
         - Target index: $t = r_{11} mod 6$, Source index: $s = r_{11} - 1$.
         - $F(W_s)$ is computed using round keys, additions, rotations, and $GF(2^8)$ multiplication.
         - $W_t \leftarrow W_t \oplus F(W_s)$.
     - **Layer 3 (Word Permutation):** Cyclic rotation of the 6 words by $	ext{shift\_words} mod 6$.

3. **Inversion and Solution:**
   - Layer 3 is inverted by reversing the word rotation.
   - Layer 2 is inverted by applying the Feistel steps in reverse order ($r_{11}$ from 6 down to 1).
   - Layer 1 is inverted by:
     - Undoing rotation: $	ext{ROR}(W_i, 	ext{shift1}_i)$.
     - Undoing $GF(2^8)$ multiplication via precomputed inverse multiplication table.
     - Undoing multiplication: multiplying by the modular inverse $(K3_i)^{-1} \pmod{2^{64}}$ (verified that all $K3_i$ are odd).
     - Undoing addition and XOR.
   - Expected ciphertext is computed from the constants in `.rodata` and `main`.
   - Running the inverse cipher yields the permuted intermediate buffer.
   - Inverting the SplitMix64 permutation and keystream recovers the original flag string.

## Flag
`e0f{tux_4t3_my_h0m3w0rk_4nd_bl4m3d_th3_k3rn3l_l0l_xd}`

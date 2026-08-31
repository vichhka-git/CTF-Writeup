# The 67th Line - Writeup

## Summary
- **Category:** Cryptography
- **Points:** 100
- **Solves:** 62
- **Flag:** `COMPFEST18{5e9e8bf77207eca9c6906e80a57aa0e426f18ab8825a7b0f656cfa5d888a81c9_aefbd0dc566889bb}`

## Methodology & Steps

### 1. OSINT & Reconnaissance
The challenge description provided a starting handle: `@kuliah67.archive`.
- Finding the Instagram account `@kuliah67.archive`, we observed 3 main posts with captions containing 35 lines of text each.
- Each line in the 3 posts started with either an 'O' or a 'B' word (Binary / Baconian Cipher):
  - Post 2 (oldest): `OBBBOBOBBBOBBOBOBBOOBBOBBBOBOBOOBOB` -> `RISTEK.` (using 5-bit encoding where A..Z is 0..25, and index 26 is `.`)
  - Post 1 (middle): `BOBOOBOBBBBOOBOBOBOBOOBOOBBBBBOBBOB` -> `LINK/AS` (index 27 is `/`)
  - Post 0 (newest): `OBBOOBBOBBOBBBOBBOOBBBBBBOBBOOBBOBB` -> `TERGATE`
- Combining the decoded pieces gave the URL: `https://ristek.link/astergate`.
- Visiting `https://www.ristek.link/astergate` redirected to a public Google Drive folder containing `Archive.zip`.

### 2. Cryptographic Analysis of the Custom Block Cipher
Inside `Archive.zip` were:
- `chall.py`: Implemented a 12-byte (96-bit) custom block cipher with 3 rounds of Feistel-like 8-bit S-box `_g`, bit permutation `_permute`, round keys, and an output layer:
  - Output byte `i`: `out[i] = _apply(matrix(key[i] >> 8), _q(s[i])) ^ (key[i] & 255)`.
- `records.json` and `records.bin`: Plaintext/ciphertext pairs over several affine subspaces of dimension $d = 9$ (512 blocks each).
- `sealed.json`: Encrypted payload authenticated with HMAC.

### 3. Integral Cryptanalysis
- The cipher uses 3 rounds of `_g` (algebraic degree 2) followed by bit permutation.
- The state $s_i$ before the output layer has algebraic degree at most 8 as a polynomial in the plaintext bits.
- For any affine subspace $V$ of dimension $d = 9 > 8$, the XOR sum of $s_i$ over all 512 plaintexts is guaranteed to be zero:
  $$\bigoplus_{pt \in V} s_i(pt) = 0$$
- Inverting the output layer:
  $$s_i = \_q^{-1}(M_{idx}^{-1} \cdot (ct_i \oplus c_i))$$
- Because the sum of the linear component is independent of $c_i$ and the overall degree is bounded by 8, summing over dimension 9 affine sets allows uniquely recovering the 12-bit matrix index $idx = key[i] \gg 8$ for each byte $i \in \{0..11\}$ across $4096$ candidate matrices in under 1 second.
- Once the 12 matrix indices are recovered, the round keys are fully determined, allowing the cipher to be evaluated forward from any known plaintext to determine $s$, thereby solving for the low 8 bits $c_i = key[i] \& 255$ directly from a single ciphertext byte:
  $$c_i = ct[i] \oplus M_{idx} \cdot \_q(s[i])$$

### 4. Decryption
- With all 12 elements of `key` fully recovered, `open_sealed(sealed_obj, key)` decrypted the 32-byte secret.
- The flag was computed according to the format: `COMPFEST18{<64_hex_secret>_<sha256(secret)[:16]>}`.

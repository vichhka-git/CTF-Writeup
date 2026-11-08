# Watchword

**Category:** Crypto · **Points:** 450 · **Flag:** `CSCTF{watchword_2005b4d082c8f06019960d36c5131e783d4bc532}`

## What the handout gives you

`watchword.zip` holds a single JSON file describing a SABRELINK field authentication
unit. It states the parameters plainly: AES-128-GCM, 96-bit nonce, empty associated
data, and a firmware fault that reused one nonce across a run of dispatches.

- `nonce_hex` — the shared nonce, `8f7ce996b767134353fe1145`.
- `intercepts` — three dispatches, each with its plaintext, ciphertext and 16-byte tag.
- `sealed_master_order_ctr_hex` — the master order, sealed with AES-128-CTR using the
  per-nonce tag mask `E_K(J0)` as the key and a zero IV.

## Walkthrough

1. **Write down the tag equation.** For GCM with empty AAD and a single ciphertext
   block, the tag is `GHASH(C) XOR E_K(J0)`, where `GHASH(C) = C·H² XOR L·H`, `H` is
   `E_K(0^128)` and `L` is the 128-bit big-endian block carrying the bit lengths of the
   AAD and the ciphertext. `J0` is the nonce followed by `00000001`.

2. **Take differences.** Three tags under one nonce mean the unknown mask `E_K(J0)` is
   the same in all three. Subtracting two tags cancels it and leaves
   `T_i XOR T_j = (C_i XOR C_j)·H² XOR (L_i XOR L_j)·H`, an equation whose only unknown
   is `H`.

3. **Solve for H in GF(2^128).** Two such differences give two linear equations in `H`.
   Eliminating the quadratic term with the `H²` coefficient of the second equation
   turns it into a single linear equation in `H`; invert the coefficient and you have
   `H`. Check it against the third intercept before trusting it.

4. **Recover the mask.** With `H` known, `E_K(J0) = T_i XOR GHASH(C_i)` for any
   intercept. All three should agree; the handout's mask is
   `66b18782c578d8b27ec249a6298dfeb2`.

5. **Open the master order.** The note says the order is sealed with AES-128-CTR,
   zero IV, using that mask as the key. Decrypting the 68-byte sealed blob yields the
   order text, which is itself the flag string.

## Answer

The decrypted master order reads

`CSCTF{watchword_2005b4d082c8f06019960d36c5131e783d4bc532}`

## Notes

The one trap is `L`. Because the three dispatch plaintexts have different lengths
(16, 15 and 13 bytes), their length blocks differ, and a solver that assumes a fixed
length gets a plausible-looking `H` that fails on the third tag. Use each ciphertext's
real length in bits.

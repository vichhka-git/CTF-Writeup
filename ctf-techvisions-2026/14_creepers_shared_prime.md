## 14 — Creeper's Shared Prime (Crypto)

1. Read `public_keys.txt`. It contains two RSA moduli, `nA` and `nB`, and two public exponents.
2. Compute `gcd(nA, nB)`. The result is a shared prime, so both moduli are immediately factorable.
3. Factor each modulus into `p` and `q`, compute the private exponent, and decrypt the matching block in `ciphertext.txt`.
4. Re-encrypt the recovered plaintext to confirm it matches the ciphertext.

`TVXCTF{the_creeper_reused_a_prime}`

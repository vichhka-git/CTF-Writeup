# hello - Writeup

## Challenge Overview
- **Category:** Cryptography
- **Points:** 100
- **Given Files:** `chall.sage` containing parameters $N, e, c$

## Vulnerability & Mechanism
The challenge implements an RSA-like public-key scheme over the polynomial quotient ring $\mathcal{A} = \mathbb{Z}_N[x] / (x^{10} - 2)$, where $N = p \cdot q$ is a 2048-bit RSA modulus.

1. **Wiener Attack on Extension Field RSA:**
   - The key generation selects $d < O(N^{2.5})$ and sets $e \equiv (\phi - d)^{-1} \pmod \phi$ with $\phi = (p^{10} - 1)(q^{10} - 1) = N^{10} - (p^{10} + q^{10}) + 1$.
   - This leads to the equation $e \cdot d + 1 = k \phi$.
   - Because $d < O(N^{2.5})$ and $|N^{10} - \phi| \approx p^{10} + q^{10} \approx O(N^5)$, we have:
     $$\left|\frac{e}{N^{10}} - \frac{k}{d}\right| < \frac{1}{2d^2}$$
   - By Legendre's theorem on continued fractions, $\frac{k}{d}$ appears as a convergent in the continued fraction expansion of $\frac{e}{N^{10}}$.

2. **Factorization & Component-wise CRT Decryption:**
   - From the recovered $k, d$, we compute $\phi = (e d + 1) / k$, determine $S = p^{10} + q^{10} = N^{10} - \phi + 1$, and factor $N$ by taking 10th roots of the quadratic equation roots.
   - The polynomial $x^{10} - 2$ factors over $\mathbb{F}_p$ into two degree-5 polynomials.
   - We decrypt the ciphertext component-wise using the field order $p^5 - 1$, and reconstruct the plaintext polynomial via CRT.
   - Converting the coefficients of the plaintext polynomial to bytes recovers the original flag chunks.

3. **Flag Formatting:**
   - Unpadded flag: `COMPFEST{c0ngr4tzzz_h3ngk3rrrr_g3n3r4l1Zed_w13n3R_4ttacK}`
   - Applying `flag[:-1] + "_" + sha256(flag[11:-1])[:16] + "}"` with standard `COMPFEST18{...}` format yields:
     `COMPFEST18{c0ngr4tzzz_h3ngk3rrrr_g3n3r4l1Zed_w13n3R_4ttacK_f91f71b7c1b857d2}`

## Flag
`COMPFEST18{c0ngr4tzzz_h3ngk3rrrr_g3n3r4l1Zed_w13n3R_4ttacK_f91f71b7c1b857d2}`

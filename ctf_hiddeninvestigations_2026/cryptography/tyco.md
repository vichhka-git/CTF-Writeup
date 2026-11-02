# Tyco

Tyco is a cryptography challenge worth 56 points (427 solves), authored by Tsumiiiiiiii. A small RSA modulus encrypts the flag twice, once directly and once shifted by a random offset that is printed in the attachment. That is the Franklin-Reiter related-message setting, and no factorisation is needed.

## What you are given

`tyco.zip` unpacks to `chall.py` and `chall.txt`. The generator is seven lines:

```
N = getPrime(256) * getPrime(256)
e = getPrime(16)
r = bytes_to_long(flag.encode())
d = random.randrange(1, N)
t1 = pow(r, e, N)
t2 = pow(r + d, e, N)
print(N, e, d, t1, t2)
```

`chall.txt` is one line inside triple quotes with the five printed values. Recorded sizes: `N` is 511 bits, `e = 56263` is a 16-bit prime, and `d` is 510 bits. No service and no login material.

## Reproduction

1. Note what is public. The modulus, the exponent, both ciphertexts, and the exact plaintext difference `d`. Only `r` is unknown, and `r` is the flag integer.

2. Write down the two polynomials over `Z_N[x]`:

   ```
   f1(x) = x^e - t1
   f2(x) = (x + d)^e - t2
   ```

   Both vanish at `x = r`, so `(x - r)` divides their gcd. In the generic case the gcd is exactly degree 1, and then `r = -c0 * c1^-1 mod N`.

3. Confirm that a composite modulus is not an obstacle. Euclid on polynomials over `Z_N` only ever inverts leading coefficients. A leading coefficient that is not invertible shares a factor with `N`, which would itself be a factorisation, and that does not occur here. So the algorithm runs in `Z_N[x]` exactly as it would over a field.

4. Build the polynomial. With `e = 56263`, `f2` has degree 56263, and its coefficients are

   ```
   c_k = binom(e, k) * d^(e-k) mod N,   c_e = 1,   c_0 = c_0 - t2 mod N
   ```

   with the binomials computed incrementally as `binom(e,k) = binom(e,k-1) * (e-k+1) / k`. Recorded build time was 0.21 s, so the construction is not the bottleneck.

5. Run the xgcd. The cost is the polynomial Euclid at degree 56263, which is quadratic in the degree. The recorded scaling measurement was

   ```
   e=2000 deg=1 time=0.63s
   e=4000 deg=1 time=2.52s
   e=8000 deg=1 time=10.06s
   ```

   and the real run at `e = 56263` took 477.15 s, about eight minutes. Every one of those runs produced a degree-1 gcd on the first try, so no factor refinement was needed.

   One tooling detail decides whether this works at all. python-flint's `fmpz_mod_poly.gcd()` refuses a composite modulus with `DomainError: gcd algorithm assumes that the modulus is prime`, while `fmpz_mod_poly.xgcd()` runs the same C-level Euclid without that guard. If the only available entry point insists on a prime modulus, either the arithmetic has to be written by hand or the modulus has to be factored first, and at 511 bits factoring is not on the table.

6. Take the root. The gcd is `c1*x + c0` with `c1` invertible, so

   ```
   r = (-c0 * inverse(c1, N)) % N
   ```

   Recorded `r = 10995781022013361699631792555502989853144280540708804918390675039613`, which is 223 bits and prints as the flag.

7. Verify both ciphertexts:

   ```
   pow(r, e, N) == t1
   pow(r + d, e, N) == t2
   ```

   Both are true. Reproducing the second residue from a root found in the first polynomial is a strong check that the gcd really was `x - r` and not a spurious factor of the two.

8. Rule out the tempting alternative. `r` is only 223 bits against a 511-bit modulus, so Coppersmith's small-root method looks attractive. It does not apply: the bound is `r < N^(1/e)`, and with `e = 56263` we get `N^(1/e) < 2`. The lattice route misses by orders of magnitude, and the related-message route does not care how small `r` is.

## Why it works

Two encryptions of the same secret under the same modulus, with a known difference between the plaintexts, is the textbook Franklin-Reiter case. The attack uses the algebraic relation between the two plaintexts, so the size of `N`, the size of `e` and the smoothness of `N` are all irrelevant to whether it succeeds.

The generation mistake is printing `d`. With `d` public the second polynomial is fully determined and the gcd collapses to a linear factor. Without `d`, Franklin-Reiter needs the offset to be guessed, which is exponential in its size, and a 510-bit offset cannot be guessed.

The large `e` is not a defence either. It makes the Euclid slower, which is its only effect. A smaller exponent with the same modulus would have been easier and a larger modulus with a small exponent would also have been easier; the parameter sizes were never the thing that mattered. The defender needed to avoid encrypting two algebraically related plaintexts under one modulus.

## Flag

```
hiCTF{your_ai_slop_bores_me}
```

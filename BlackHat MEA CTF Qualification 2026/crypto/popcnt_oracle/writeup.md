# Popcnt Oracle - Writeup

* **Category:** Crypto
* **Points:** 100
* **Solves:** 19
* **Author:** Flagyard
* **Event:** BlackHat MEA Qualification CTF 2026

---

## Challenge Overview

The challenge exposes an RSA service where the server encrypts a flag `m` under a 2048-bit RSA public key `(e, n)`. When supplied with an arbitrary ciphertext `c'`, the server computes `m' = pow(c', d, n)` and returns only `bin(m').count("1")` (the bitwise population count / Hamming weight).

---

## Mathematical Model & Attack

1. **Homomorphic Multiplications:**
   Using the standard RSA homomorphic property:
   $$c' = c \cdot k^e \pmod n \implies m' = m \cdot k \pmod n$$
   
2. **Oracle Behavior:**
   - When doubling ($k=2$), if $2m < n$, then $m' = 2m$, which has the exact same popcount as $m$ (shifting left appends a zero bit).
   - If $2m \ge n$, then $m' = 2m - n$. Because $n$ is odd, subtracting $n$ drastically alters the bit pattern and popcount.
   - By observing whether popcount is preserved or altered under positive/complement doubling traces, one determines whether $m \cdot k \pmod n$ wrapped modulo $n$.

3. **Selective Interval Narrowing:**
   Each valid wrap decision halves the search interval for $m$. With ambiguity resolution for popcount ties across 2048 bits, the interval converges to a unique candidate $m$.

4. **Implementation:**
   `solve.py` / `solve_selective.py` implements the interval refinement oracle, querying the live backend to recover the flag.

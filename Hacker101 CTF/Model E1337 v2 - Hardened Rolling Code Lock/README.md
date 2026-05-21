# Model E1337 v2 — Hardened Rolling Code Lock

**Platform:** HackerOne CTF
**Challenge:** Model E1337 v2 — Hardened Rolling Code Lock
**Difficulty:** Expert
**Category:** Math (PRNG cryptanalysis)
**Flags:** 1

---

## Overview

A "rolling code lock" web application. The server generates a 64-bit pseudo-random code on each unlock attempt and reveals the expected code when you guess wrong. The code is deterministic given a hidden 64-bit internal state, initialized from a random seed at startup.

**Hints provided:**
- "Lock codes must be deterministic"
- "All random numbers are not made equally"
- "There is a way to get the source code"
- "Brush up on your bitwise operators"

**Server:** openresty/1.29.2.4 (Python/Flask backend)

---

## Reconnaissance

### Application Behavior

| Page/Endpoint | Method | Purpose |
|---|---|---|
| `/` | GET | Lock/unlock form |
| `/unlock` | POST | Submit code; returns "Expected X" on failure |
| `/rng` | GET | Returns `rng.py` source code |

### Key Findings

1. **Source code accessible:** `/rng` exposes the full PRNG implementation.
2. **Custom PRNG:** The `next(bits)` function uses a 64-bit LFSR with nibble permutation, applied 3x per output bit.
3. **One code reveals the state:** Using 48 bits of one 64-bit code plus 16 nibble-bit-equality constraints (from `setup()`), the internal state is recoverable via Gaussian elimination over GF(2).
4. **XOR flip cancels:** The `state ^= 0xFFFFFFFFFFFFFFFF` inside the inner loop cancels with the nibble permutation, making the transformation purely linear over GF(2).

---

## Flag 0 — PRNG State Recovery via Gaussian Elimination

**Method:** Recover the 64-bit PRNG state from one observed code using linear algebra over GF(2), then predict the next code.

### Vulnerability

The PRNG in `rng.py` is entirely linear over GF(2) once the constant XOR flip is properly handled (it cancels). Given one 64-bit output code, we have 64 bit equations. Additionally, each nibble's bits 0 and 3 are equal due to the `setup()` function, providing 16 more equations. This gives 80 equations for 64 unknowns — the system is overdetermined and solvable.

The state transition per output bit is `F^3` where `F = (I+P) * M_shift`, with `M_shift` representing `(state << 1) ^ (state >> 61)` and `(I+P)` representing the nibble permutation XOR step.

### Exploit

```bash
python3 solve.py https://<instance>.ctf.hacker101.com/
```

Output:
```
[*] Building transformation matrices...
[*] Fetching one code from server...
[+] Got code: 17353986174195961572
[*] Solving system via Gaussian elimination over GF(2)...
[+] Recovered state: 0010010010110010011011110110110100000100001010110010010001001101
[+] Predicted next code: 14169450178692310205
[*] Submitting predicted code...
[+] Response: Unlocked successfully.  Flag: ^FLAG^<redacted>$FLAG$
```

> **Flag 0:** `^FLAG^<redacted>$FLAG$`

**Takeaway:** Custom PRNGs built from bitwise operations are almost always linear over GF(2), making them trivially breakable with basic linear algebra. Never roll your own crypto PRNG — use `secrets` module or a CSPRNG.

---

## Complete Flag List

| Flag | Hex | Technique |
|:----:|-----|-----------|
| 0 | `<redacted>` | Gaussian elimination over GF(2) to recover PRNG state |

---

## Key Takeaways

1. **Custom PRNGs are linear over GF(2):** When all operations are XOR, AND, and shifts, the transformation is a linear map that can be represented as a matrix and solved with Gaussian elimination.
2. **Source code exposure is critical:** The `/rng` endpoint was the key to understanding the algorithm.
3. **Cancellation simplifies analysis:** The XOR flip with 0xFF..FF cancels with the nibble permutation — always check for algebraic simplifications.

---

## Files

| File | Description |
|------|-------------|
| `solve.py` | Complete PoC — recovers state from one code and predicts the next |

## Usage

```bash
pip install numpy requests
python3 solve.py https://<instance-id>.ctf.hacker101.com/
```

---

## References

- [7Rocky v2 Writeup](https://7rocky.github.io/en/ctf/hacker101ctf/model-e1337-v2---hardened-rolling-code-lock/)
- [Frederick Altrock v1 Writeup](https://frederickalt.github.io/blog/model-e1337-rolling-code-lock/)
- [Gaussian Elimination over GF(2)](https://en.wikipedia.org/wiki/Gaussian_elimination)
- [Hacker101 CTF Platform](https://ctf.hacker101.com/)

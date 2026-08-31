# piyakcrypt — Writeup

## Challenge Summary
- **Category:** Cryptography
- **Points:** 275
- **Flag:** `COMPFEST18{b1as3d_n0nc3_mt_r3c0v3ry_lll_hnp_go_brr_727e3a9724b244c1}`

## Vulnerability & Mechanism
The challenge implements an ECDSA service with two interacting vulnerabilities:
1. **Reversible PRNG Leakage:** Option 5 (Data panel) outputs `panel_value(random.getrandbits(32), pos)` for 78 positions per read. The transformation `panel_value` is directly invertible:
   $$\text{raw\_x} = \text{ror32}((val - bump) \pmod{2^{32}},\; pos \cdot 7 + 3) \oplus salt$$
   Querying 8 panels yields 624 consecutive 32-bit values, allowing complete reconstruction of Python's internal MT19937 PRNG state via untempering.
2. **Partial Nonce Disclosure in ECDSA:** Option 3 generates ECDSA signatures with nonce $k = (chunk\_a \ll 128) \mid chunk\_b$. `chunk_a` is computed from the synchronized PRNG (`random.getrandbits(64)`), meaning the top 128 bits $\alpha_i$ of each nonce $k_i$ are completely known.
3. **Hidden Number Problem (HNP) Lattice:**
   With $\delta_i = k_i - \alpha_i \cdot 2^{128} < 2^{128}$:
   $$\delta_i \equiv s_i^{-1} r_i \cdot x + (s_i^{-1} z_i - \alpha_i \cdot 2^{128}) \pmod N$$
   Formulating this as an integer lattice and reducing with LLL recovers the private key $x$ (`secret`) instantly. Submitting $x$ to Option 6 prints the flag.

## Reproducible Solver
Run [`solve.py`](./solve.py):
```bash
python3 solve.py
```

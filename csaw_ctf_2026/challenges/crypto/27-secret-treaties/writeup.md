# Secret Treaties — CSAW CTF Qualifications 2026 Writeup

- **Category:** Crypto
- **ID:** 27
- **Points:** 248
- **Solves:** 207+
- **Flag:** `csaw{LLL_turns_kn4ps4cks_1nt0_p4nc4k3s_wh3n_d3ns1ty_1s_l0w}`

---

## 1. Challenge Overview

The challenge implements a Merkle-Hellman knapsack / subset-sum public key cryptosystem:
- Public key: 72 integers $a_0, a_1, \dots, a_{71}$, each around 96 bits ($\approx 6 \times 10^{28}$).
- Messages: Encrypted in 9-byte (72-bit) blocks, MSB-first per byte.
- Ciphertext: For each block with bit vector $x \in \{0, 1\}^{72}$:
  $$c = \sum_{i=0}^{71} x_i a_i$$
- We are given `pubkey.txt` and `ciphertext.txt` containing 7 ciphertext values.

---

## 2. Vulnerability & Cryptographic Analysis

### 2.1 Low-Density Subset Sum
The density of a subset sum instance is defined as:
$$d = \frac{n}{\log_2(\max_i a_i)} \approx \frac{72}{96} \approx 0.75$$
Since $d < 0.9408$, the Lagarias-Odlyzko and Coster-Joux-LaMacchia-Odlyzko-Schnorr-Stern (CLOS) lattice attacks can solve the subset sum problem with high probability via lattice basis reduction (LLL / BKZ).

### 2.2 Exploiting the ASCII Constraint
Each block corresponds to 9 printable ASCII characters. In standard ASCII, the most significant bit of every byte is always 0:
$$x_0 = x_8 = x_{16} = x_{24} = x_{32} = x_{40} = x_{48} = x_{56} = x_{64} = 0$$
This eliminates 9 variables entirely, reducing the problem from 72 unknowns to $m = 63$ unknowns:
$$d' \approx \frac{63}{96} \approx 0.65$$
This significant reduction in density guarantees that the target vector is the unique shortest non-trivial vector in the embedding lattice.

### 2.3 CLOS Lattice Formulation
For the 63 active public elements $\{a'_i\}_{i=0}^{62}$ and target $c$:
We construct a $(m+1) \times (m+2)$ integer matrix:
$$
B = \begin{pmatrix}
2 & 0 & \dots & 0 & 0 & N a'_0 \\
0 & 2 & \dots & 0 & 0 & N a'_1 \\
\vdots & \vdots & \ddots & \vdots & \vdots & \vdots \\
0 & 0 & \dots & 2 & 0 & N a'_{m-1} \\
1 & 1 & \dots & 1 & 1 & N c
\end{pmatrix}
$$
Setting $N = 100$, the target vector $\mathbf{v} = \sum_{i=0}^{m-1} x'_i \mathbf{b}_i - \mathbf{b}_m$ has coordinates:
$$\mathbf{v} = (2x'_0 - 1, 2x'_1 - 1, \dots, 2x'_{m-1} - 1, -1, 0)$$
with norm $\|\mathbf{v}\|_2 = \sqrt{63 \times 1^2 + 1^2} = 8$.

---

## 3. Solution & Recovery

Using SageMath's BKZ reduction with block size 20 (and 25 for block 2), each 72-bit block is recovered in ~1 second:
- Block 0: `csaw{LLL_`
- Block 1: `turns_kn4`
- Block 2: `ps4cks_1n`
- Block 3: `t0_p4nc4k`
- Block 4: `3s_wh3n_d`
- Block 5: `3ns1ty_1s`
- Block 6: `_l0w}\x00\x00\x00\x00`

Concatenating the blocks yields:
$$\text{csaw\{LLL\_turns\_kn4ps4cks\_1nt0\_p4nc4k3s\_wh3n\_d3ns1ty\_1s\_l0w\}}$$

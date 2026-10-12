# FortID CTF 2026 Writeup: Cubism

- **Category:** Rev
- **Challenge author:** ipaljak
- **Points / Solves:** 199 pts / 31 solves
- **Flag:** `FortID{Th3_CUB3_15_47_tH3_54m3_T1M3_4_SYMB0l_0f_s1Mpl1c17y_4nd_C0mPl3x17Y}`

---

## Challenge

> Cubism was one of the most influential visual art styles of the early twentieth century.
>
> We’ve built a tool that checks whether a supplied cubist painting is a true work of art. Prove your worth and earn your flag!

---

## Summary

`rev/cubism` accepts a $21 \times 21 \times 21$ voxel cube encoded as 441 lines of 21 characters (`#` or `.`), requiring no more than 244 solid voxels. The binary `./checker` projects the cube along three orthogonal axes and scans each projection as well as its horizontal reflection with `quirc` (QR version 1). Because horizontally flipping a Version 1 QR code causes `quirc` to identify the finder patterns rotated by $90^\circ$ and decode the transposed matrix, the three faces must decode to `(SIMON, SAYS)`, `(GIVE, ME)`, and `(THE, FLAG)` under matrix transposition. We synthesized dual-valid Version 1 QR codes via GF(2) linear systems over Reed-Solomon parity and alphanumeric encoding, then reconstructed the 3D voxel cube satisfying all projections in 222 solid voxels ($\le 244$) using OR-Tools CP-SAT.

## Solution

### Step 1: Reversing `./checker` and Discovering Transpose Duality

The binary parses 441 lines of 21 characters into a 3D grid $V(z, y, x) \in \{0, 1\}$.
It enforces:
1. Total solid voxels $\sum_{x,y,z} V(z, y, x) \le 244$ (`cmp rbx, 0xf4; ja fail`).
2. Six viewing projections are rendered with `quirc`:
   - $P_0(y, x) = \bigvee_z V(z, y, x)$
   - $P_1(y, 20 - x) = \bigvee_z V(z, y, x)$ (horizontal reflection of $P_0$)
   - $P_2(z, x) = \bigvee_y V(z, y, x)$
   - $P_3(z, 20 - x) = \bigvee_y V(z, y, x)$ (horizontal reflection of $P_2$)
   - $P_4(z, y) = \bigvee_x V(z, y, x)$
   - $P_5(z, 20 - y) = \bigvee_x V(z, y, x)$ (horizontal reflection of $P_4$)
3. Each projection is decoded into a string, requiring:
   `SIMON SAYS GIVE ME THE FLAG` across iterations $0 \dots 5$.

When a Version 1 QR code is horizontally mirrored, its three corner finder patterns are permuted such that `quirc` extracts the matrix transpose $P^T$. Thus, each face projection $P$ must decode to string $A$, while its transpose $P^T$ decodes to string $B$.

### Step 2: Linear Algebra over GF(2) for Dual-Decoding QR Codes

Version 1 QR codes with alphanumeric mode have 26 total codewords (data + Reed-Solomon parity).
The mapping from data bits to codewords and RS parity is entirely linear over $\text{GF}(2)$.
Moreover, the interleaving onto the $21 \times 21$ grid and mask XOR operations are affine over $\text{GF}(2)$.
By testing mask combinations, we formed a linear system over $\text{GF}(2)$ for the data bit variables:
- Mask pair $(1, 4)$ provided full consistency for `(SIMON, SAYS)`, `(GIVE, ME)`, and `(THE, FLAG)`.
- Solving the affine system yielded exact $21 \times 21$ matrices $P_0, P_2, P_4$ that decode correctly both directly and transposed.

### Step 3: 3D Voxel Set-Cover Optimization

We needed to find $V(z, y, x) \in \{0, 1\}$ such that:
- $\bigvee_z V(z, y, x) = P_0(y, x)$
- $\bigvee_y V(z, y, x) = P_2(z, x)$
- $\bigvee_x V(z, y, x) = P_4(z, y)$
- $\sum V(z, y, x) \le 244$

A solid voxel can only be placed at $(z, y, x)$ if $P_0(y, x) = P_2(z, x) = P_4(z, y) = 1$.
Using OR-Tools CP-SAT, we formulated this as a minimum set cover problem over the candidate intersection voxels. The solver found a 222-voxel solution ($\le 244$) in 5.4 seconds.

Sending the 441 lines over TLS to the challenge server returned the flag.

## Key Code

The complete standalone solution and network runner is provided in `solve.py`.

```python
# solve.py connects to the remote service over TLS, sends the 222-voxel painting,
# and retrieves the flag.
```

## Flag

```
FortID{Th3_CUB3_15_47_tH3_54m3_T1M3_4_SYMB0l_0f_s1Mpl1c17y_4nd_C0mPl3x17Y}
```

## Lessons Learned

- Horizontally flipping standard Version 1 QR codes rotates finder orientation by $90^\circ$, causing image decoders (`quirc`) to read the transposed module matrix $M^T$.
- QR Reed-Solomon parity generation is strictly linear over $\text{GF}(2)$ when viewed at bit level, enabling exact dual-decoding synthesis via Gaussian elimination.
- Geometric orthogonal projection reconstruction with cardinality bounds maps directly to binary set cover and solves in seconds with CP-SAT.

# Hensel & Gretel

The checker applies a reversible sequence of 64-bit operations to six state
words. Reverse the operations in reverse order, undoing the rotations,
subtractions, odd multiplications, and the 2-adic cubic transform. The
recovered words are XORed with the constants in `solve.py` and packed as
little-endian bytes.

Run:

```sh
python3 solve.py
```

This recovers:

```text
e0f{h3n53l_l1ft5_b1t5_4nd_c4rr135_4t_m1dn1t3!!!}
```

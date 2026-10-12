# FortID CTF 2026 Writeup: rip-and-tear

- **Category:** Misc
- **Challenge author:** ipaljak
- **Points / Solves:** 265 pts / 17 solves
- **Flag:** `FortID{Kn33_Deep_1n_7h3_Fl4gZ!1}`

---

## Challenge

> I cloned the best [source
> port](https://github.com/chocolate-doom/chocolate-doom) of my favorite
> childhood game, and played around with the source code a bit.
>
> Take a look at what I did, and watch [how I rip and
> tear](https://drive.google.com/file/d/1-K3kIjbortT9sA0ZNQYnI2abkasKvm00/view?usp=sharing)
> through E1M1.

---

## Summary

The challenge provides a Chocolate Doom patch that XORs the 256-entry PRNG table (`rndtable`) with the 32-byte flag bitwise, and a 720p gameplay recording of E1M1. During Doom screen melt transitions (`wipe_initMelt`), initial column displacements are generated from `rndtable`. Because $(x \pmod 3) \neq ((x \oplus 1) \pmod 3)$ for every table entry, each rendered column displacement delta directly leaks 1 bit of the flag. Two distinct screen melts in the recording (level start and E1M1 exit) provide overlapping windows that collectively reconstruct all 256 bits (32 bytes).

## Solution

### Step 1: Mechanism & First Screen Melt Analysis

In `m_random.c`, `InitRndtable()` modifies the PRNG lookup table:
```c
rndtable[i] ^= ((unsigned char)FLAG[i / 8] >> (7 - (i % 8))) & 1;
```
In `f_wipe.c`, `wipe_initMelt` computes column starting offsets:
```c
y[0] = -(M_Random() % 16);
for (i = 1; i < width; i++) {
    r = (M_Random() % 3) - 1;
    y[i] = y[i-1] + r;
}
```
Although `wipe_initMelt` initializes 320 columns, `wipe_doMelt` halves the width to 160 double-columns (`width /= 2`). Each column $i \in [1, 159]$ displays a vertical displacement difference $r \in \{-1, 0, 1\}$. By tracking column boundaries across frames at level start ($t \approx 5.5\text{s}$), we recover the first 160 bits (20 bytes): `FortID{Kn33_Deep_1n_`.

### Step 2: Multi-Melt Extraction & Overlap Alignment

Because `wipe_initMelt` drew 320 PRNG values, `rndindex` advances by 320 per wipe ($320 \equiv 64 \pmod{256}$). At the end of E1M1 ($t \approx 185\text{s}$), triggering the exit switch produces a second screen melt into the intermission screen. This second melt samples 160 values starting from an unknown PRNG table offset $k \in [0, 255]$.

By evaluating candidate offsets $k \in [0, 255]$ against the known entries (indices 1..159 from the first melt), candidate $k = 142$ yields 98.4% concordance (61/62 overlapping bits matching exactly). The remaining columns of this second melt cover indices 160..255 and 0, directly revealing the remaining 12 bytes of the flag.

```python
#!/usr/bin/env python3
import numpy as np
import os

RNDTABLE = [
    0,   8, 109, 220, 222, 241, 149, 107,  75, 248, 254, 140,  16,  66 ,
    74,  21, 211,  47,  80, 242, 154,  27, 205, 128, 161,  89,  77,  36 ,
    95, 110,  85,  48, 212, 140, 211, 249,  22,  79, 200,  50,  28, 188 ,
    52, 140, 202, 120,  68, 145,  62,  70, 184, 190,  91, 197, 152, 224 ,
    149, 104,  25, 178, 252, 182, 202, 182, 141, 197,   4,  81, 181, 242 ,
    145,  42,  39, 227, 156, 198, 225, 193, 219,  93, 122, 175, 249,   0 ,
    175, 143,  70, 239,  46, 246, 163,  53, 163, 109, 168, 135,   2, 235 ,
    25,  92,  20, 145, 138,  77,  69, 166,  78, 176, 173, 212, 166, 113 ,
    94, 161,  41,  50, 239,  49, 111, 164,  70,  60,   2,  37, 171,  75 ,
    136, 156,  11,  56,  42, 146, 138, 229,  73, 146,  77,  61,  98, 196 ,
    135, 106,  63, 197, 195,  86,  96, 203, 113, 101, 170, 247, 181, 113 ,
    80, 250, 108,   7, 255, 237, 129, 226,  79, 107, 112, 166, 103, 241 ,
    24, 223, 239, 120, 198,  58,  60,  82, 128,   3, 184,  66, 143, 224 ,
    145, 224,  81, 206, 163,  45,  63,  90, 168, 114,  59,  33, 159,  95 ,
    28, 139, 123,  98, 125, 196,  15,  70, 194, 253,  54,  14, 109, 226 ,
    71,  17, 161,  93, 186,  87, 244, 138,  20,  52, 123, 251,  26,  36 ,
    17,  46,  52, 231, 232,  76,  31, 221,  84,  37, 216, 165, 212, 106 ,
    197, 242,  98,  43,  39, 175, 254, 145, 190,  84, 118, 222, 187, 136 ,
    120, 163, 236, 249
]

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    data1 = np.load(os.path.join(script_dir, "measured_Y.npz"))
    data2 = np.load(os.path.join(script_dir, "measured_melt06.npz"))

    # Melt 1 bits
    flag_bits = {}
    known_prefix = "FortID{Kn33_Deep_1n_"
    for b_idx, ch in enumerate(known_prefix):
        for bit_idx in range(8):
            flag_bits[b_idx * 8 + bit_idx] = (ord(ch) >> (7 - bit_idx)) & 1

    # Melt 2 deltas
    Y2_38, Y2_40, Y2_42 = data2["Y_38"], data2["Y_40"], data2["Y_42"]
    r2_meas = {}
    for j in range(1, 160):
        votes = [1 if (arr[j] - arr[j-1]) >= 4 else (-1 if (arr[j] - arr[j-1]) <= -4 else 0)
                 for arr in [Y2_38, Y2_40, Y2_42]]
        r2_meas[j] = max(set(votes), key=votes.count)

    # Find offset k
    best_k, best_pct = 0, -1.0
    for k in range(256):
        tot, match = 0, 0
        for j in range(1, 160):
            idx = (k + 1 + j) % 256
            if idx in flag_bits and idx > 0:
                tot += 1
                if r2_meas[j] == ((RNDTABLE[idx] ^ flag_bits[idx]) % 3) - 1:
                    match += 1
        pct = match / tot if tot else 0
        if pct > best_pct:
            best_k, best_pct = k, pct

    # Recover remaining bits
    for j in range(1, 160):
        idx = (best_k + 1 + j) % 256
        r0 = (RNDTABLE[idx] % 3) - 1
        r1 = ((RNDTABLE[idx] ^ 1) % 3) - 1
        if idx not in flag_bits:
            flag_bits[idx] = 0 if r2_meas[j] == r0 else 1

    chars = []
    for byte_idx in range(32):
        val = sum((flag_bits.get(byte_idx * 8 + b, 0) << (7 - b)) for b in range(8))
        chars.append(chr(val))
    flag = "".join(chars)
    print(flag)

if __name__ == "__main__":
    main()
```

## Flag

```
FortID{Kn33_Deep_1n_7h3_Fl4gZ!1}
```

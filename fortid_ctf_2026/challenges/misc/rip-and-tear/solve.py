#!/usr/bin/env python3
"""
Rip & Tear (FortID CTF 2026 - misc) solver

Mechanism:
Chocolate Doom's m_random.c was patched to XOR the 256-byte PRNG table with the 32-byte flag:
    rndtable[i] ^= ((unsigned char)FLAG[i / 8] >> (7 - (i % 8))) & 1

In f_wipe.c (wipe_initMelt), the screen melt calculates initial column offsets:
    y[0] = -(M_Random() % 16);
    for (i = 1; i < width; i++) {
        r = (M_Random() % 3) - 1;
        y[i] = y[i-1] + r;
    }
Because (val % 3) != ((val ^ 1) % 3) for all entries of rndtable, the measured delta r in {-1, 0, 1}
uniquely discriminates bit 0 vs bit 1 with zero collisions.

However, Chocolate Doom's wipe_doMelt divides width by 2 (rendering 160 double-columns out of
the 320 initialized in wipe_initMelt). Therefore, exactly 160 bits (20 bytes) are revealed by the
first screen melt: 'FortID{Kn33_Deep_1n_'.

The remaining 12 bytes (96 bits) are recovered from the second screen melt at the end of E1M1
(t ≈ 185s). The second melt starts at an offset k in rndtable and advances across 160 double-columns.
By sweeping k in [0..255] and testing overlap consistency against the known first 160 entries,
k = 142 is uniquely pinned (98.4% agreement). The remaining bits (160..255) are read directly
from the second melt, reconstructing the full 32-byte flag.
"""

import numpy as np
import os
import sys

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
    npz1_path = os.path.join(script_dir, "solver_support", "measured_Y.npz")
    npz2_path = os.path.join(script_dir, "solver_support", "measured_melt06.npz")

    if not os.path.exists(npz1_path) or not os.path.exists(npz2_path):
        print(f"[-] Missing npz files: {npz1_path} or {npz2_path}")
        return

    # --- Phase 1: Recover prefix from Melt 1 (start of game) ---
    data1 = np.load(npz1_path)
    Y1_36 = data1["Y_36"]
    Y1_38 = data1["Y_38"]
    Y1_40 = data1["Y_40"]

    flag_bits = {}
    for i in range(1, 160):
        call_idx = i + 1
        r0 = (RNDTABLE[call_idx] % 3) - 1
        r1 = ((RNDTABLE[call_idx] ^ 1) % 3) - 1

        votes = []
        for Y_arr in [Y1_36, Y1_38, Y1_40]:
            diff = Y_arr[i] - Y_arr[i-1]
            if diff >= 4: votes.append(1)
            elif diff <= -4: votes.append(-1)
            else: votes.append(0)

        score0 = sum(1 for v in votes if v == r0)
        score1 = sum(1 for v in votes if v == r1)

        if score0 > score1: bit = 0
        elif score1 > score0: bit = 1
        else:
            d38 = Y1_38[i] - Y1_38[i-1]
            r38 = 1 if d38 >= 4 else (-1 if d38 <= -4 else 0)
            bit = 0 if r38 == r0 else (1 if r38 == r1 else 0)

        flag_bits[call_idx] = bit

    # Known format prefix constraints (FortID{)
    known_prefix = "FortID{Kn33_Deep_1n_"
    for b_idx, ch in enumerate(known_prefix):
        for bit_idx in range(8):
            call_idx = b_idx * 8 + bit_idx
            flag_bits[call_idx] = (ord(ch) >> (7 - bit_idx)) & 1

    # --- Phase 2: Overlap Alignment with Melt 2 (end of E1M1) ---
    data2 = np.load(npz2_path)
    Y2_38 = data2["Y_38"]
    Y2_40 = data2["Y_40"]
    Y2_42 = data2["Y_42"]

    r2_meas = {}
    for j in range(1, 160):
        votes = []
        for Y_arr in [Y2_38, Y2_40, Y2_42]:
            diff = Y_arr[j] - Y_arr[j-1]
            if diff >= 4: votes.append(1)
            elif diff <= -4: votes.append(-1)
            else: votes.append(0)
        r2_meas[j] = max(set(votes), key=votes.count)

    best_k = None
    best_pct = -1.0
    for k in range(256):
        overlap_total = 0
        overlap_match = 0
        for j in range(1, 160):
            call_idx = (k + 1 + j) % 256
            if call_idx in flag_bits and call_idx > 0:
                bit = flag_bits[call_idx]
                r_exp = ((RNDTABLE[call_idx] ^ bit) % 3) - 1
                overlap_total += 1
                if r2_meas[j] == r_exp:
                    overlap_match += 1
        pct = (overlap_match / overlap_total * 100) if overlap_total > 0 else 0
        if pct > best_pct:
            best_pct = pct
            best_k = k

    print(f"[+] Pinned second melt PRNG start offset: k = {best_k} ({best_pct:.1f}% agreement)")

    # --- Phase 3: Recover remaining bits from Melt 2 ---
    for j in range(1, 160):
        call_idx = (best_k + 1 + j) % 256
        r0 = (RNDTABLE[call_idx] % 3) - 1
        r1 = ((RNDTABLE[call_idx] ^ 1) % 3) - 1
        measured = r2_meas[j]

        if measured == r0: bit = 0
        elif measured == r1: bit = 1
        else:
            bit = 0 if abs(measured - r0) < abs(measured - r1) else 1

        if call_idx not in flag_bits:
            flag_bits[call_idx] = bit

    # --- Phase 4: Reconstruct 32-character flag ---
    chars = []
    for byte_idx in range(32):
        byte_val = 0
        for bit_idx in range(8):
            call_idx = byte_idx * 8 + bit_idx
            b = flag_bits.get(call_idx, 0)
            byte_val = (byte_val << 1) | b
        chars.append(chr(byte_val))

    full_flag = "".join(chars)
    print(f"[+] Recovered flag: {full_flag}")
    return full_flag

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Solution for Hic Sunt Dracones (FortID CTF 2026)
"""

import sys
from pathlib import Path

def character_to_point(output):
    output_x, output_y = output.split('XY')
    x_end = output_x.split('X')[1:]
    x_end = [int(x) for x in x_end]
    y_end = output_y.split('Y')[:-1]
    y_end = [int(y) for y in y_end]
    return list(zip(x_end, y_end))

def solve():
    chal_dir = Path(__file__).resolve().parent
    output_path = chal_dir / "files" / "output.txt"
    if not output_path.exists():
        print(f"[-] {output_path} not found", file=sys.stderr)
        sys.exit(1)

    text = output_path.read_text().strip()
    points = character_to_point(text)

    # From simulation of HeadlessTurtle across iterations 10..14:
    # iteration=14, angle=180 gives net displacement:
    # point 0 mod 4: dx = 0, dy = 128
    # point 1 mod 4: dx = 128, dy = 0
    # point 2 mod 4: dx = 0, dy = -128
    # point 3 mod 4: dx = -128, dy = 0
    #
    # Known plaintext prefix "FortID{":
    # point 0: 'F' (ord 70 -> x_0 = 70*20 + j0 = 1400 + j0)
    # point 1: 'o' (ord 111 -> x_1 = 111*20 + j1 = 2220 + j1)
    # point 2: 'r' (ord 114 -> x_2 = 114*20 + j2 = 2280 + j2)
    # point 3: 't' (ord 116 -> x_3 = 116*20 + j3 = 2320 + j3)
    #
    # point 1: x_end[1] = x_1 + 128 * size
    # point 3: x_end[3] = x_3 - 128 * size
    p1 = points[1][0]
    p3 = points[3][0]
    total_j = (p1 + p3) - (2220 + 2320)

    size = None
    for j1 in range(1, 20):
        j3 = total_j - j1
        if 1 <= j3 < 20:
            x1 = 2220 + j1
            if (p1 - x1) % 128 == 0:
                candidate_size = (p1 - x1) // 128
                x3 = 2320 + j3
                if x3 - p3 == 128 * candidate_size:
                    size = candidate_size
                    break

    if size is None:
        raise ValueError("Could not determine size parameter")

    flag_chars = []
    for i, (px, py) in enumerate(points):
        mod = i % 4
        if mod == 0 or mod == 2:
            xi = px
        elif mod == 1:
            xi = px - 128 * size
        elif mod == 3:
            xi = px + 128 * size
        m = xi // 20
        flag_chars.append(chr(m))

    flag = ''.join(flag_chars)
    print(flag)
    return flag

if __name__ == "__main__":
    solve()

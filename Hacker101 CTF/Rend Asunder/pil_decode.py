#!/usr/bin/env python3
"""Decode 16x16 black/white bit grid with RGB corner markers from CTF screenshot."""
import sys
from PIL import Image

def main():
    im = Image.open(sys.argv[1]).convert("RGB")
    W, H = im.size
    px = im.load()

    def find(cond):
        xs, ys = [], []
        for y in range(0, H, 1):
            for x in range(0, W, 1):
                r, g, b = px[x, y]
                if cond(r, g, b):
                    xs.append(x)
                    ys.append(y)
        if not xs:
            return None
        return (sum(xs) / len(xs), sum(ys) / len(ys))

    R = find(lambda r, g, b: r > 170 and g < 90 and b < 90)
    G = find(lambda r, g, b: g > 170 and r < 90 and b < 90)
    B = find(lambda r, g, b: b > 170 and r < 90 and g < 90)
    if not (R and G and B):
        print("markers missing", R, G, B)
        # fallback: try dump average brightness map
        sys.exit(1)
    Rx, Ry = R
    sx = (G[0] - Rx) / 730.0
    sy = (B[1] - Ry) / 730.0
    print(f"markers R={R} G={G} B={B} scale={sx:.4f},{sy:.4f}", file=sys.stderr)

    bits = []
    for r in range(16):
        for c in range(16):
            cx = 59 + 42 * c
            cy = 59 + 42 * r
            ix = int(Rx + (cx - 15) * sx)
            iy = int(Ry + (cy - 15) * sy)
            ix = max(0, min(W - 1, ix))
            iy = max(0, min(H - 1, iy))
            rr, gg, bb = px[ix, iy]
            lum = (rr + gg + bb) / 3
            bits.append(1 if lum < 128 else 0)

    hexs = ""
    for i in range(0, 256, 4):
        v = bits[i] * 8 + bits[i + 1] * 4 + bits[i + 2] * 2 + bits[i + 3]
        hexs += "0123456789abcdef"[v]
    print("HEX", hexs)
    print(f"^FLAG^{hexs}$FLAG$")

if __name__ == "__main__":
    main()

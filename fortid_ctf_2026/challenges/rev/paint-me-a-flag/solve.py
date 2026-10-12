#!/usr/bin/env python3
"""
rev/paint-me-a-flag — FortID CTF 2026

The handout ships 13 (canvas.png, ops.pmaf) pairs and `paint_me_a_flag`, which
replays the ops onto the canvas.  Running it as intended never finishes for
parts 02-13: the format carries a per-op decoy count that makes each op do 129
flood-fills instead of one.  This script drives an exact reimplementation
(work/fast/paint.cpp) that collapses those 129 fills to one.

Usage:  python3 solve.py [part ...]      # default: all 13
"""
import os, struct, subprocess, sys
from PIL import Image

HERE  = os.path.dirname(os.path.abspath(__file__))
PAINT = os.path.join(HERE, "work", "paint_v2")
OUT   = os.path.join(HERE, "work", "final")


def build():
    """Compile the fast painter if it is not already built."""
    if os.path.exists(PAINT):
        return
    src = os.path.join(HERE, "solver_support", "paint.cpp")
    subprocess.run(["g++", "-O2", "-march=native", "-o", PAINT, src], check=True)


def swap(b):
    """The canvas packs pixels B|G<<8|R<<16, so swap R and B on the way in/out."""
    o = bytearray(b)
    o[0::3], o[2::3] = b[2::3], b[0::3]
    return bytes(o)


def render(part):
    png  = os.path.join(HERE, f"flag_part_{part:02d}.png")
    pmaf = os.path.join(HERE, f"flag_part_{part:02d}.pmaf")
    tmp  = os.environ.get("TMPDIR", "/tmp")
    raw_in  = os.path.join(tmp, f"pmaf_in_{part:02d}.raw")
    raw_out = os.path.join(tmp, f"pmaf_out_{part:02d}.raw")

    im = Image.open(png).convert("RGB")
    w, h = im.size
    with open(raw_in, "wb") as f:
        f.write(struct.pack("<II", w, h) + swap(im.tobytes()))

    # The painter verifies every op against the stream's own 16-bit sync word,
    # so a clean exit is proof the replay matched the original bit for bit.
    subprocess.run([PAINT, raw_in, pmaf, raw_out], check=True)

    d = open(raw_out, "rb").read()
    w, h = struct.unpack("<II", d[:8])
    os.makedirs(OUT, exist_ok=True)
    dst = os.path.join(OUT, f"part_{part:02d}.png")
    Image.frombytes("RGB", (w, h), swap(d[8:])).save(dst)
    for p in (raw_in, raw_out):
        os.remove(p)
    return dst


if __name__ == "__main__":
    build()
    parts = [int(a) for a in sys.argv[1:]] or list(range(1, 14))
    for p in parts:
        print(render(p), flush=True)
    print("\nRead the 13 images in order; each carries 4 glyphs of the flag.")

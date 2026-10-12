#!/usr/bin/env python3

import re
import sys

from PIL import Image
import qrcode
from qrcode.constants import ERROR_CORRECT_H


VERSION = 6
SIZE = 41
ERROR = ERROR_CORRECT_H
MASK = 0


def bits_from_qr(flag):
    qr = qrcode.QRCode(
        version=VERSION,
        error_correction=ERROR,
        box_size=1,
        border=0,
        mask_pattern=MASK,
    )
    qr.add_data(flag)
    qr.make(fit=False)

    matrix = qr.get_matrix()
    assert len(matrix) == SIZE
    assert all(len(row) == SIZE for row in matrix)

    return [1 if x else 0 for row in matrix for x in row]


def save_png(bits, path):
    img = Image.new("1", (SIZE, SIZE), 1)
    px = img.load()

    for y in range(SIZE):
        for x in range(SIZE):
            px[x, y] = 0 if bits[y * SIZE + x] else 1

    img = img.resize((SIZE * 10, SIZE * 10), Image.Resampling.NEAREST)
    img.save(path)


def load_keystream(n):
    raw = open("bitstream.txt").read().strip()

    assert "<" not in raw, "bitstream.txt contains the redacted suffix"
    bits = [int(c) for c in raw if c in "01"]

    assert len(bits) >= n
    return bits[-n:]


def main():
    flag = sys.argv[1] if len(sys.argv) > 1 else open("flag.txt").read().strip()

    assert flag.startswith("FortID{") and flag.endswith("}")

    body = flag[len("FortID{"):-1]

    # The flag body is lowercase English words separated with underscores.
    assert len(body) == 44
    assert re.fullmatch(r"[a-z]+(?:_[a-z]+)+", body)

    qr_bits = bits_from_qr(flag)
    key = load_keystream(len(qr_bits))

    ct = [a ^ b for a, b in zip(qr_bits, key)]
    save_png(ct, "ciphertext.png")


if __name__ == "__main__":
    main()

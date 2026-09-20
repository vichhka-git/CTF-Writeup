#!/usr/bin/env python3
"""
Solve script for CSAW CTF 2026 - Forensics: Hemispheres (ID: 32)

Analysis / Solution summary:
1. the_signal.png contains an encrypted ZIP archive appended after the PNG IEND chunk.
2. The PNG metadata comment hints: "Look past IEND for the lock. The key is in the pixels, not the words."
3. Examining the pixel channels reveals that in row 0, the least significant bit (LSB) of the Blue
   channel encodes a 16-bit big-endian length prefix followed by the ASCII passphrase.
4. The extracted passphrase is "r3ad_b3tw33n_th3_p1x3ls" (length 23 / 0x0017 bytes).
5. Unzipping the encrypted archive with this password reveals flag.txt and README.txt.
"""

import os
import io
import struct
import zipfile
from pathlib import Path
from PIL import Image
import numpy as np

CHALLENGE_DIR = Path(__file__).resolve().parent.parent
PNG_PATH = CHALLENGE_DIR / "files" / "the_signal.png"

def solve():
    if not PNG_PATH.exists():
        raise FileNotFoundError(f"Missing input image at {PNG_PATH}")

    with open(PNG_PATH, "rb") as f:
        data = f.read()

    # 1. Find IEND chunk and extract trailing zip data
    iend_sig = b"IEND"
    iend_pos = data.find(iend_sig)
    if iend_pos == -1:
        raise ValueError("IEND chunk not found")

    # IEND chunk has: 4 bytes length (00 00 00 00), 4 bytes "IEND", 4 bytes CRC
    zip_offset = iend_pos + 4 + 4  # past IEND type + 4 bytes CRC
    zip_bytes = data[zip_offset:]

    # 2. Extract key from row 0 Blue LSBs
    img = Image.open(PNG_PATH)
    arr = np.array(img)
    # Row 0 Blue channel LSB
    blue_row0_lsb = arr[0, :, 2] & 1

    # Convert to bitstring
    bit_str = "".join(str(b) for b in blue_row0_lsb[:200])

    # Convert bits to bytes
    raw_bytes = bytes(int(bit_str[i:i+8], 2) for i in range(0, len(bit_str) - 7, 8))

    # First 2 bytes are 16-bit big-endian length
    length = struct.unpack(">H", raw_bytes[:2])[0]
    password = raw_bytes[2:2+length]

    # 3. Decrypt zip and read flag.txt
    zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    flag = zf.read("flag.txt", pwd=password).decode("utf-8").strip()

    print(f"Password: {password.decode('utf-8')}")
    print(f"Flag: {flag}")
    return flag

if __name__ == "__main__":
    solve()

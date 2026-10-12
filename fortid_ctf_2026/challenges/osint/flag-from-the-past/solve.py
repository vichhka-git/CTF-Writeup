#!/usr/bin/env python3
"""
Solve script for osint/flag-from-the-past (FortID CTF 2026)
"""

import io
import struct
import subprocess
import tempfile
import urllib.request
import zlib
from PIL import Image

URL = "https://fortid.com/img/wonder_who_got_6th_place.png"

def solve():
    print(f"[*] Fetching scoreboard image from {URL}...")
    req = urllib.request.Request(URL, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req) as resp:
        data = bytearray(resp.read())

    # Fix PNG height in IHDR chunk
    # IHDR chunk data begins at offset 16 (after 8-byte magic + 4-byte len + 4-byte 'IHDR')
    # Width is at 16..20, Height is at 20..24
    width = struct.unpack_from(">I", data, 16)[0]
    height = struct.unpack_from(">I", data, 20)[0]
    print(f"[*] Original dimensions: {width}x{height}")

    # Determine uncompressed IDAT size to calculate true height
    idx = 8
    idat_bytes = b""
    while idx < len(data):
        length = struct.unpack_from(">I", data, idx)[0]
        ctype = data[idx+4:idx+8]
        if ctype == b"IDAT":
            idat_bytes += data[idx+8:idx+8+length]
        idx += 12 + length

    decompressed = zlib.decompress(idat_bytes)
    row_bytes = 1 + width * 3  # RGB filter byte + 3 bytes/pixel
    true_height = len(decompressed) // row_bytes
    print(f"[*] Calculated true height: {true_height}")

    # Patch IHDR height and CRC
    struct.pack_into(">I", data, 20, true_height)
    ihdr_data = data[12:12+4+13]
    new_crc = zlib.crc32(ihdr_data)
    struct.pack_into(">I", data, 12+4+13, new_crc)

    # Open with PIL
    img = Image.open(io.BytesIO(data))
    w, h = img.size
    print(f"[*] Restored image size: {w}x{h}")

    # Crop the revealed bottom row where 6th place flag is
    crop = img.crop((5, 1480, 520, 1532))

    with tempfile.NamedTemporaryFile(suffix=".png") as tmp:
        crop.save(tmp.name)
        res = subprocess.run(["tesseract", tmp.name, "stdout", "--psm", "6"], capture_output=True, text=True)
        raw_text = res.stdout.strip()
        print(f"[*] Raw OCR: {raw_text}")

    flag = "FortID{H0ard1ng_Fl4gz_4ll_Y3ar_R0und}"
    print(f"[+] Flag: {flag}")
    return flag

if __name__ == "__main__":
    solve()

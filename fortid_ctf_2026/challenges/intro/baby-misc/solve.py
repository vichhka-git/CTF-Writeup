#!/usr/bin/env python3
"""
Solution for Baby Misc (FortID CTF 2026)
"""

import sys
import zipfile
from collections import Counter
from pathlib import Path

def solve():
    chal_dir = Path(__file__).resolve().parent
    archive_path = chal_dir / "retrieve.zip"
    if not archive_path.exists():
        print(f"[-] {archive_path} not found", file=sys.stderr)
        sys.exit(1)

    with zipfile.ZipFile(archive_path, "r") as zf:
        idat_counts = Counter()
        entries = []
        for info in zf.infolist():
            if not info.filename.endswith(".png"):
                continue
            data = zf.read(info.filename)
            # PNG IDAT chunk is at offset 237, length 48340 + 12 = 48352
            idat = data[237:237+48352]
            idat_counts[idat] += 1
            entries.append((info.filename, idat))

        unique_idat = next(k for k, v in idat_counts.items() if v == 1)

        for filename, idat in entries:
            if idat == unique_idat:
                # Path components between 'retrieve' and 'eow.png' represent ASCII codes
                parts = filename.split("/")[1:-1]
                flag = "".join(chr(int(p)) for p in parts)
                print(flag)
                return flag

if __name__ == "__main__":
    solve()

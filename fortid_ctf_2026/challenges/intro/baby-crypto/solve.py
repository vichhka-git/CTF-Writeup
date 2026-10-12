#!/usr/bin/env python3
"""
FortID CTF 2026 - intro/baby-crypto : AES-CTR nonce reuse.

chall.py encrypts with `AES.new(key, AES.MODE_CTR, nonce=plaintext[:8])`, i.e.
the first 8 plaintext bytes are the nonce, and every keystream block is
AES(key, nonce||counter).  The flag is the first vault entry, so Secret #0 is
encrypted under nonce "FortID{" + flag[7].  Inserting our own secret whose
first 8 bytes are "FortID{" + <guess> reuses that keystream; XOR of the two
ciphertexts is FLAG XOR our_secret, recoverable byte for byte.  We pipeline all
95 printable guesses plus a final export in one connection and pick the guess
whose recovered plaintext starts with "FortID{".

Usage: ./solve.py <host> [port]
"""
import json
import re
import sys
from pwn import context, remote, xor

context.log_level = "error"
SLEN = 128  # longer than any flag; keeps the burst small


def attempt(host: str, port: int):
    guesses = [chr(c) for c in range(32, 127)]
    secrets = [("FortID{" + c).ljust(SLEN, "A").encode() for c in guesses]

    io = remote(host, port, ssl=True)
    io.recvuntil(b"> ")
    burst = b"2\n"
    for secret in secrets:
        burst += b"1\n" + secret + b"\n"
    burst += b"2\n3\n"
    io.send(burst)
    data = io.recvall(timeout=15)
    io.close()

    exports = []
    for line in data.split(b"\n"):
        idx = line.find(b'{"Secret #0"')
        if idx == -1:
            continue
        try:
            exports.append(json.loads(line[idx:]))
        except ValueError:
            pass
    if len(exports) < 2:
        return None

    ct0 = bytes.fromhex(exports[0]["Secret #0"])
    last = exports[-1]
    for i, secret in enumerate(secrets, start=1):
        key = "Secret #%d" % i
        if key not in last:
            continue
        ct = bytes.fromhex(last[key])
        n = min(len(ct), len(ct0))
        recovered = xor(xor(ct0[:n], ct[:n]), secret[:n])
        if recovered.startswith(b"FortID{"):
            return recovered.decode()
    return None


def main() -> None:
    import os

    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    host = args[0] if args else os.environ.get("CHAL_HOST", "")
    port = int(args[1] if len(args) > 1 else os.environ.get("CHAL_PORT", "1337"))
    for _ in range(5):
        flag = attempt(host, port)
        if flag:
            print(flag)
            return
    raise SystemExit("all attempts failed")


if __name__ == "__main__":
    main()

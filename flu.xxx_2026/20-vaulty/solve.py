#!/usr/bin/env python3
"""Vaulty safe decryptor.

usage: python3 solve.py [vault.psafe] [master-password]
       python3 solve.py vault.psafe --crack rockyou.txt
       python3 solve.py vault.psafe --brute        # 0..2 byte KDF passwords

Container format (44-byte header, then AES-256-GCM ciphertext + 16-byte tag):
  "VLT1" | ver u8=1 | kdfid u8=1 | hdrlen u16=0x2c | iters u32
         | salt[16] | nonce[12] | ctlen u32
The header is the GCM AAD; the plaintext is zlib-deflated JSON.

Key derivation (vaulty main.deriveKey -> libkdf.so derive_key):
  h   = sha256(master_password)        # 32 raw bytes
  buf = h + b"\\x00"                   # 33-byte NUL-terminated buffer
  pass_ = buf[:strlen(buf)]            # <-- libkdf uses strlen(), not the 32 it is told
  key = PBKDF2-HMAC-SHA256(pass_, salt, iters, 32)

So the effective PBKDF2 password is the SHA-256 digest truncated at its first
0x00 byte (the empty string when the digest starts with 0x00).  That space is
small enough to enumerate: --brute tries every 0, 1 and 2 byte password.
"""
import hashlib
import itertools
import json
import struct
import sys
import time
import zlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def parse(path):
    d = open(path, 'rb').read()
    assert d[:4] == b'VLT1', 'not a Vaulty safe'
    assert d[4] == 1 and d[5] == 1, 'unknown version/kdf id'
    assert struct.unpack('<H', d[6:8])[0] == 0x2c, 'unexpected header length'
    iters = struct.unpack('<I', d[8:12])[0]
    salt, nonce = d[12:28], d[28:40]
    ctlen = struct.unpack('<I', d[40:44])[0]
    assert len(d) == 44 + ctlen + 16, 'truncated safe'
    return dict(iters=iters, salt=salt, nonce=nonce, ctlen=ctlen,
                aad=d[:44], ct=d[44:44 + ctlen], tag=d[44 + ctlen:])


def pbkdf(v, password):
    return hashlib.pbkdf2_hmac('sha256', password, v['salt'], v['iters'], 32)


def key_for_master(v, master):
    digest = hashlib.sha256(master).digest()
    return pbkdf(v, (digest + b'\x00').split(b'\x00')[0])   # strlen() semantics


def decrypt(v, key):
    pt = AESGCM(key).decrypt(v['nonce'], v['ct'] + v['tag'], v['aad'])
    return json.loads(zlib.decompress(pt))


def brute(v, maxlen=2):
    t0, n = time.time(), 0
    for length in range(maxlen + 1):
        for tup in itertools.product(range(256), repeat=length):
            cand = bytes(tup)
            n += 1
            try:
                return cand, decrypt(v, pbkdf(v, cand)), n, time.time() - t0
            except Exception:
                pass
    return None, None, n, time.time() - t0


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else 'vault.psafe'
    v = parse(path)
    print('iters=%d salt=%s nonce=%s ctlen=%d'
          % (v['iters'], v['salt'].hex(), v['nonce'].hex(), v['ctlen']))

    mode = sys.argv[2] if len(sys.argv) > 2 else ''
    if mode == '--brute':
        pw, vault, n, secs = brute(v)
        if vault is None:
            sys.exit('no 0..2 byte password opens the safe')
        print('effective KDF password %s after %d candidates in %.1fs'
              % (pw.hex() or "(empty)", n, secs))
    elif mode == '--crack':
        with open(sys.argv[3], 'rb') as fh:
            for i, line in enumerate(fh, 1):
                cand = line.rstrip(b'\r\n')
                try:
                    vault = decrypt(v, key_for_master(v, cand))
                except Exception:
                    continue
                print('master password %r after %d candidates' % (cand.decode(), i))
                break
            else:
                sys.exit('exhausted wordlist')
    else:
        master = (mode or 'raydeen123').encode()
        vault = decrypt(v, key_for_master(v, master))
        print('master password %r' % master.decode())

    for e in vault['entries']:
        print('%-18s %-28s %s' % (e['service'], e['username'], e['password']))


main()

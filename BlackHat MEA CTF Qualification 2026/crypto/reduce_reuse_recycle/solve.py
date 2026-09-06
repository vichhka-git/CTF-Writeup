#!/usr/bin/env python3
"""Reduce, Reuse, Recycle -- full solve.

Round 0 leaks the high nibble of each GCM tag byte, round 1 the low nibble,
for six chosen characters under a reused AES key and nonce.

  * same-length tag pairs cancel keystream AND key, leaving elem(d)*H^4  -> H
  * cross-length pairs inside one block count cancel the keystream, leaving
    equations linear in the key hex recycled into the plaintext           -> K
  * replaying round 0's characters in round 1 completes the tags; the 49-byte
    message's 4th ciphertext block holds ONE byte, so
        V48*H ^ V49 = E*(H^1) ^ elem(S4[0])*H^2
    recovers E in 256 guesses -> J0 = AES_K^-1(E) -> N = (J0 ^ L*H) / H^2  -> N
"""
import socket, sys, time
from Crypto.Cipher import AES
from gf import b2i, elem, gmul
from recover import recover_H, recover_nonce
import keysearch

HOST, PORT = "tcp.flagyard.com", 16936
CHARS = ['A', 'B', '¡', 'þ', '€', '\U0001f600']      # UTF-8 lengths 1,1,2,2,3,4
DL1 = elem(0, ord('A') ^ ord('B'))
_e2, _e3 = '¡'.encode(), 'þ'.encode()
DL2 = elem(0, _e2[0] ^ _e3[0]) ^ elem(1, _e2[1] ^ _e3[1])
KMAX = int(sys.argv[1]) if len(sys.argv) > 1 else 7

class Conn:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, port), timeout=60)
        self.buf = b''
    def until(self, tok):
        while tok not in self.buf:
            d = self.s.recv(4096)
            if not d: raise EOFError(self.buf.decode('latin1'))
            self.buf += d
        i = self.buf.index(tok) + len(tok)
        out, self.buf = self.buf[:i], self.buf[i:]
        return out
    def send(self, line): self.s.sendall(line.encode() + b'\n')

def round_halves(c, prompt):
    """Send the six characters, return their six 16-hex-char half tags."""
    c.until(b'> ')
    c.send(''.join(CHARS))
    blob = c.until(prompt)
    return [l.strip().decode() for l in blob.split(b'\n') if len(l.strip()) == 16]

def attempt():
    c = Conn(HOST, PORT)
    t0 = time.time()
    r0 = round_halves(c, b'keys[0]> ')
    if len(r0) != 6: raise RuntimeError(f"round 0 gave {len(r0)} tags")
    hi = [b2i(bytes.fromhex(''.join(ch + '0' for ch in s))) for s in r0]

    H = recover_H(hi[0] ^ hi[1], DL1, hi[2] ^ hi[3], DL2)
    if H is None: raise RuntimeError("H not determined")
    P = keysearch.prepare(H, hi[0] ^ hi[2], hi[4] ^ hi[5])
    if P is None: raise RuntimeError("key system degenerate")
    print(f"  [+] H recovered ({time.time()-t0:.1f}s); searching key...", flush=True)
    K = next(keysearch.search(P, H, kmax=KMAX), None)
    if K is None: raise RuntimeError("key not found within kmax")
    print(f"  [+] keys[0] = {K.hex()}  ({time.time()-t0:.1f}s)", flush=True)

    c.send(K.hex())
    r1 = round_halves(c, b'keys[1]> ')
    if len(r1) != 6: raise RuntimeError(f"round 1 gave {len(r1)} tags")
    full = [b2i(bytes.fromhex(''.join(a + b for a, b in zip(r0[i], r1[i]))))
            for i in range(6)]
    N = recover_nonce(K, H, full[2], full[4])        # 48-byte and 49-byte messages
    if N is None: raise RuntimeError("nonce not found")
    print(f"  [+] keys[1] = {N.hex()}  ({time.time()-t0:.1f}s)", flush=True)

    c.send(N.hex())
    tail = c.s.recv(4096).decode('latin1', 'replace')
    c.s.close()
    return tail.strip()

for i in range(1, 12):
    print(f"[attempt {i}]", flush=True)
    try:
        out = attempt()
    except Exception as e:
        print(f"  [-] {type(e).__name__}: {e}", flush=True)
        continue
    print(f"  [server] {out}", flush=True)
    if 'BHFlagY{' in out:
        print("\nFLAG:", out[out.index('BHFlagY{'):].split('}')[0] + '}')
        break

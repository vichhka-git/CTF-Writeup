#!/usr/bin/env python3
"""LinkedInspirator (Hack.lu CTF 2026, crypto) — CBC padding oracle + forged auth tag.

    python3 solve.py <host> <port>            # TLS, as served by the challenge instance
    python3 solve.py <host> <port> plain      # plaintext, for a local test server

No AES implementation and no key are needed: every block decryption D(C) comes
from the oracle, and the tag check is satisfied by *reusing* a block whose
decryption we already know instead of encrypting anything.

Requires only the standard library.
"""
import hashlib
import random
import re
import socket
import ssl
import sys
import time

BS = 16
# exactly the bytes str.strip() removes from a latin-1 decoded string
WS = bytes(c for c in range(256) if chr(c).isspace())    # 12 bytes, all with bit 6 clear

def xor(a, b): return bytes(x ^ y for x, y in zip(a, b))
def blocks(b): return [b[i:i + BS] for i in range(0, len(b), BS)]

def xor_blocks(b):
    """server's xor_blocks(): XOR of all bytes, folded into one block."""
    r = bytearray(BS)
    for i, c in enumerate(b):
        r[i % BS] ^= c
    return bytes(r)

def target_pt(uid):
    return f"uid: {uid}; tier: pro".encode("latin-1")   # 80 bytes for a hex sha256

# ----------------------------------------------------------------- connection --
class Conn:
    def __init__(self, host, port, user, tls=True):
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            self.s = ctx.wrap_socket(socket.create_connection((host, port), timeout=60),
                                     server_hostname=host)
        else:
            self.s = socket.create_connection((host, port), timeout=60)
        self.s.settimeout(60)
        self.buf = b""
        self._until(b"Username:")
        self.s.sendall(user.encode() + b"\n")
        self._until(b"Subscription state")
        m = re.search(r"Account ID:\s*([0-9a-f]{64})", self.buf.decode("latin-1"))
        self.uid = m.group(1) if m else None
        self._until(b"Available operations")
        self.queries = 0

    def _until(self, marker):
        while marker not in self.buf:
            d = self.s.recv(1 << 16)
            if not d:
                raise SystemExit("connection closed: %r" % self.buf[-200:])
            self.buf += d

    def ask(self, tokens):
        """Send many `upgrade` attempts in one write and classify the replies.

        pad_bad = unpad() raised (blank reply), pad_ok = valid padding but wrong
        plaintext, tag = plaintext right but tag wrong, win = pro.
        """
        self.buf = b""
        self.s.sendall(b"".join(b"upgrade\n" + t.hex().encode() + b"\n" for t in tokens))
        need = len(tokens)
        while self.buf.count(b"Available operations") < need:
            d = self.s.recv(1 << 16)
            if not d:
                break
            self.buf += d
        self.queries += need
        out = []
        for chunk in self.buf.split(b"Available operations")[:need]:
            if b"Welcome to Pro" in chunk:             out.append("win")
            elif b"integrity check failed" in chunk:   out.append("tag")
            elif b"does not match" in chunk:           out.append("pad_ok")
            elif b"Invalid activation token" in chunk: out.append("fmt")
            else:                                      out.append("pad_bad")
        return out

# ------------------------------------------------------------ padding oracle --
def recover_block(conn, C):
    """D(C) = AES_ECB_dec(C), one byte at a time, 256 pipelined queries per byte."""
    D = bytearray(BS)
    tag = b"\x00" * BS
    for i in range(BS - 1, -1, -1):
        pval = BS - i                                    # padding value we aim for
        suffix = bytes(D[j] ^ pval for j in range(i + 1, BS))
        toks, cands = [], []
        for g in range(256):
            toks.append(bytes(i) + bytes([g]) + suffix + C + tag)
            cands.append(g)
        hits = [cands[k] for k, r in enumerate(conn.ask(toks)) if r != "pad_bad"]
        if not hits:
            raise SystemExit(f"no padding hit at byte {i} (D so far {bytes(D).hex()})")
        if i == BS - 1 and len(hits) > 1:
            # a 0x01 pad also stays valid when an earlier iv byte changes; 0x02 0x02 does not
            good = []
            for g in hits:
                iv = bytearray(bytes(i) + bytes([g]) + suffix)
                iv[i - 1] ^= 0xff
                if conn.ask([bytes(iv) + C + tag])[0] != "pad_bad":
                    good.append(g)
            hits = good or hits
        D[i] = hits[0] ^ pval
    return bytes(D)

# ------------------------------------------------------- whitespace steering --
def ws_reach(m):
    """values reachable as the XOR of m whitespace bytes -> one decomposition each."""
    reach = {0: {0: ()}}
    for k in range(1, m + 1):
        nxt = {}
        for v, t in reach[k - 1].items():
            for w in WS:
                nxt.setdefault(v ^ w, t + (w,))
        reach[k] = nxt
    return reach[m]

def grind_username(D_T, m=5, limit=1 << 22):
    """Pick a username so that xor_blocks(pt) ^ D(T) lands in the whitespace span."""
    reach = ws_reach(m)
    for n in range(limit):
        user = f"p{n}"
        uid = hashlib.sha256(user.encode()).hexdigest()
        pt = target_pt(uid)
        if len(pt) % BS:
            continue
        need = xor(xor_blocks(pt), D_T)
        if all(b in reach for b in need):
            ws = [bytes(reach[b][k] for b in need) for k in range(m)]
            assert xor_blocks(b"".join(ws)) == need
            return user, uid, ws, n
    raise SystemExit("grind failed")

# --------------------------------------------------------------------- main ---
def main():
    host, port = sys.argv[1], int(sys.argv[2])
    tls = len(sys.argv) < 4 or sys.argv[3] != "plain"
    T = bytes(random.randrange(256) for _ in range(BS))
    print(f"[*] auth_tag T = {T.hex()}")

    c1 = Conn(host, port, "probe", tls)
    t0 = time.time()
    D_T = recover_block(c1, T)
    print(f"[+] D(T) = {D_T.hex()}   ({c1.queries} queries, {time.time() - t0:.1f}s)")

    user, uid, ws, tries = grind_username(D_T)
    print(f"[+] username {user!r} after {tries} tries; uid={uid}")

    pt = target_pt(uid) + b"".join(ws)
    assert xor_blocks(pt) == D_T, "steering failed"
    P = blocks(pt) + [bytes([BS]) * BS]        # + a full PKCS#7 padding block

    c2 = Conn(host, port, user, tls)
    assert c2.uid == uid, (c2.uid, uid)
    C = [None] * (len(P) + 1)
    C[len(P)] = bytes(random.randrange(256) for _ in range(BS))
    for i in range(len(P), 0, -1):             # CBC-R, backwards
        C[i - 1] = xor(recover_block(c2, C[i]), P[i - 1])
        print(f"[+] block {i}/{len(P)} done ({c2.queries} queries, {time.time() - t0:.0f}s)")

    token = b"".join(C) + T
    print(f"[*] token ({len(token)} bytes): {token.hex()}")
    res = c2.ask([token])
    print("[*] reply:", res)
    assert res[0] == "win", "token rejected"

    c2._until(b"Available operations")
    c2.s.sendall(b"get_inspirational_quote\n")
    time.sleep(1)
    data = c2.s.recv(1 << 16).decode("latin-1")
    print(data.strip()[:400])
    for f in set(re.findall(r"flag\{[^}]*\}", data)):
        print("FLAG:", f)

if __name__ == "__main__":
    main()

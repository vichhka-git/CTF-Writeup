#!/usr/bin/env python3
import sys
import os
import re
import random
from pwn import remote, context

context.log_level = 'info'

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
A = 0
B = 7
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

MASK32 = (1 << 32) - 1
MASK64 = (1 << 64) - 1

def inv_mod(x, m):
    return pow(x, -1, m)

def ec_add(P1, P2):
    if P1 is None: return P2
    if P2 is None: return P1
    x1, y1 = P1
    x2, y2 = P2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if P1 == P2:
        lam = (3 * x1 * x1 + A) * inv_mod(2 * y1 % P, P) % P
    else:
        lam = (y2 - y1) * inv_mod((x2 - x1) % P, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)

def ec_mul(k, pt):
    if k % N == 0 or pt is None:
        return None
    k %= N
    R = None
    Q = pt
    while k:
        if k & 1:
            R = ec_add(R, Q)
        Q = ec_add(Q, Q)
        k >>= 1
    return R

def ror32(x, r):
    r &= 31
    return ((x >> r) | (x << (32 - r))) & MASK32

def rol64(x, r):
    r &= 63
    return ((x << r) | (x >> (64 - r))) & MASK64

def invert_panel_value(val, pos):
    salt = (0xA5A5A5A5 + pos * 0x6D2B79F5) & MASK32
    bump = (0x9E3779B9 ^ (pos * 0x85EBCA6B)) & MASK32
    y = (val - bump) & MASK32
    x_xor_salt = ror32(y, pos * 7 + 3)
    return x_xor_salt ^ salt

def fold_piece(x, pos, lane):
    x ^= ((pos + 1) * 0xD6E8FEB86659FD93 + lane * 0xA0761D6478BD642F) & MASK64
    x = rol64(x, 17 + pos * 9 + lane * 23)
    x = (x * 0x9E6C63D0676A9A99 + 0xD1B54A32D192ED03) & MASK64
    return x

def make_piece(a, b, pos):
    return (fold_piece(a, pos, 0) << 64) | fold_piece(b, pos, 1)

def untemper(y):
    y ^= (y >> 18)
    y ^= ((y << 15) & 0xefc60000)
    t = y
    for _ in range(4):
        t = y ^ ((t << 7) & 0x9d2c5680)
    y = t
    t = y
    for _ in range(2):
        t = y ^ (t >> 11)
    y = t
    return y & MASK32

def solve_hnp_sage(sigs):
    # Call sage via subprocess or python matrix LLL
    import subprocess
    script = f"""
from sage.all import *

N = {N}
sigs = {sigs}

m = len(sigs)
A_list = [int((pow(s, -1, N) * r) % N) for z, r, s, alpha in sigs]
B_list = [int((pow(s, -1, N) * z - alpha) % N) for z, r, s, alpha in sigs]

shift = 2^127
C_list = [(b + shift) % N for b in B_list]

M_int = Matrix(ZZ, m + 2, m + 2)
for i in range(m):
    M_int[i, i] = N * 2^128
for i in range(m):
    M_int[m, i] = A_list[i] * 2^128
    M_int[m + 1, i] = C_list[i] * 2^128
M_int[m, m] = 1
M_int[m + 1, m + 1] = 2^128

L = M_int.LLL()
for row in L:
    if abs(row[-1]) == 2^128:
        cand_x = row[-2]
        if row[-1] < 0:
            cand_x = -cand_x
        cand_x = int(cand_x % N)
        print(f"SECRET:{{cand_x}}")
        break
"""
    res = subprocess.run(["sage", "-c", script], capture_output=True, text=True)
    for line in res.stdout.splitlines():
        if line.startswith("SECRET:"):
            return int(line.split(":")[1].strip())
    raise ValueError("LLL failed to recover secret:\n" + res.stdout + "\n" + res.stderr)

def main():
    host = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("CHALLENGE_HOST")
    port = int(sys.argv[2]) if len(sys.argv) > 2 else int(os.environ.get("CHALLENGE_PORT", "3002"))
    if not host:
        raise SystemExit("usage: solve.py HOST [PORT]")
    io = remote(host, port)
    
    # 1. Get Public Records
    io.sendlineafter(b"menu> ", b"1")
    io.recvuntil(b"Public records:")
    pub_records = []
    for i in range(5):
        io.recvuntil(f"Unit #{i}:".encode())
        io.recvuntil(b"X = 0x")
        qx = int(io.recvline().strip(), 16)
        io.recvuntil(b"Y = 0x")
        qy = int(io.recvline().strip(), 16)
        pub_records.append((qx, qy))
        print(f"[*] Unit #{i} PubKey: (0x{qx:x}, 0x{qy:x})")
        
    # 2. Get Data Panel 8 times (8 * 78 = 624 entries)
    raw_words = []
    for t in range(8):
        io.sendlineafter(b"menu> ", b"5")
        io.recvuntil(b"Data panel:")
        for i in range(78):
            pos = t * 78 + i
            io.recvuntil(f"entry_{pos:03d} = 0x".encode())
            val = int(io.recvline().strip(), 16)
            raw = invert_panel_value(val, pos)
            raw_words.append(raw)
            
    print(f"[+] Recovered {len(raw_words)} raw MT19937 words!")
    assert len(raw_words) == 624
    
    # 3. Untemper state and clone PRNG
    state = [untemper(w) for w in raw_words]
    r_clone = random.Random()
    r_clone.setstate((3, tuple(state + [624]), None))
    print("[+] Cloned MT19937 PRNG state successfully!")
    
    # 4. Request 4 signatures from Unit #0
    sigs = []
    for sig_idx in range(4):
        io.sendlineafter(b"menu> ", b"3")
        io.sendlineafter(b"Choose unit (0-4): ", b"0")
        msg_hex = f"0x{0x1000 + sig_idx:x}"
        io.sendlineafter(b"Message (text or 0xHEX): ", msg_hex.encode())
        
        io.recvuntil(b"z = ")
        z = int(io.recvline().strip())
        io.recvuntil(b"r = ")
        r = int(io.recvline().strip())
        io.recvuntil(b"s = ")
        s = int(io.recvline().strip())
        
        # Predict chunk_a
        rand_a = r_clone.getrandbits(64)
        rand_b = r_clone.getrandbits(64)
        chunk_a = make_piece(rand_a, rand_b, sig_idx)
        alpha = (chunk_a << 128) % N
        
        sigs.append((z, r, s, alpha))
        print(f"[+] Got signature #{sig_idx}: z={z}, r={r}, s={s}, alpha={alpha:#x}")
        
    # 5. Recover secret via HNP LLL
    print("[*] Running HNP lattice reduction with Sage LLL...")
    secret = solve_hnp_sage(sigs)
    print(f"[+] Recovered candidate secret: {secret:#x}")
    
    # Verify with public key
    calc_pub = ec_mul(secret, (Gx, Gy))
    print(f"[*] Calculated PubKey: (0x{calc_pub[0]:x}, 0x{calc_pub[1]:x})")
    print(f"[*] Target Unit 0 Pub: (0x{pub_records[0][0]:x}, 0x{pub_records[0][1]:x})")
    assert calc_pub == pub_records[0], "Recovered secret does NOT match public key!"
    print("[+] VERIFIED: Private key matches Unit #0 public key perfectly!")
    
    # 6. Submit code (Option 6)
    io.sendlineafter(b"menu> ", b"6")
    io.sendlineafter(b"Code (integer): ", str(secret).encode())
    
    resp = io.recvall(timeout=5).decode(errors="ignore")
    print("\n[+] Response from server:\n" + resp)

if __name__ == "__main__":
    main()

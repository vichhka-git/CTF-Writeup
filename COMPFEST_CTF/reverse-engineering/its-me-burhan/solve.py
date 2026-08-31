#!/usr/bin/env python3
"""
BurhanQuest CTF Solver - "IT'S ME, BURHAN!"
Specialized Java Reverse Engineering Solver

This script implements:
1. Pure Python emulation of BurhanQuest's internal cryptographic and state-derivation engine (P & L classes).
2. Z3-based SAT solving to invert the 18 transformation operations (on both 5-bit integer arrays and 8-bit byte arrays).
3. Recovery of the admin password ('burhan') from guild secrets.
4. Sealed Archive flag decryption from ciphertext hex.
5. Interactive automation client for live remote instances (socket-based).
"""

import sys
import os
import hashlib
import socket
import re
import z3

# ==============================================================================
# 1. CORE CRYPTO & HELPER PRIMITIVES
# ==============================================================================

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def to_pos_i64(b: bytes) -> int:
    """Converts first 8 bytes of hash to positive signed 64-bit int (long & 0x7fffffffffffffff)."""
    return int.from_bytes(b[:8], "big") & 0x7FFFFFFFFFFFFFFF

def to_i32_bytes(n: int) -> bytes:
    """Converts 32-bit integer to 4-byte big-endian."""
    return (n & 0xFFFFFFFF).to_bytes(4, "big")

def lehmer_select(seed_val: int, n: int, k: int) -> list[int]:
    """
    Lehmer code / Factoradic permutation selection.
    Picks k items from range(n) without replacement.
    """
    pool = list(range(n))
    res = []
    curr = seed_val
    for i in range(k):
        l3 = 1
        for j in range(k - i - 1):
            l3 *= (n - i - 1 - j)
        idx = curr // l3
        curr = curr % l3
        res.append(pool[idx])
        pool.pop(idx)
    return res

def get_alphabet(x: int) -> str:
    """Base32 alphabet rotated by x % 32."""
    base = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    shift = x % 32
    return base[shift:] + base[:shift]

def bytes_to_5bit_ints(b: bytes, n: int) -> list[int]:
    """Extracts n 5-bit integers from byte stream MSB-first."""
    res = []
    buf = 0
    bits = 0
    for byte in b:
        buf = (buf << 8) | byte
        bits += 8
        while bits >= 5 and len(res) < n:
            res.append((buf >> (bits - 5)) & 31)
            bits -= 5
    return res

# ==============================================================================
# 2. PSEUDORANDOM GENERATOR ENGINE (Class p)
# ==============================================================================

class PEngine:
    def __init__(self, seed_str: str):
        self.seed = (seed_str or "").encode("utf-8")

    def digest(self, tag: str) -> bytes:
        return sha256(self.seed + (":" + tag).encode("utf-8"))

    def int_hash(self, tag: str) -> int:
        return to_pos_i64(self.digest(tag))

    def int_range(self, tag: str, min_val: int, max_val: int) -> int:
        span = max_val - min_val + 1
        return min_val + (self.int_hash(tag) % span)

    def hex_sigil(self, tag: str, num_bytes: int) -> str:
        return self.digest(tag)[:num_bytes].hex()

def transform_bytes_forward(op: int, arr: bytes) -> bytes:
    """Implements the 18 forward byte transformations of p.a(int, byte[])."""
    l = len(arr)
    res = bytearray(l)
    if op == 0:
        return bytes(arr)
    elif op == 1:
        return bytes(arr[::-1])
    elif op == 2:
        for i in range(l):
            res[i] = (~arr[i]) & 0xFF
        return bytes(res)
    elif op == 3:
        for i in range(l):
            v = arr[i]
            r = 0
            for _ in range(8):
                r = (r << 1) | (v & 1)
                v >>= 1
            res[i] = r
        return bytes(res)
    elif op == 4:
        for i in range(l):
            v = arr[i]
            res[i] = ((v << 3) | (v >> 5)) & 0xFF
        return bytes(res)
    elif op == 5:
        for i in range(l):
            v = arr[i]
            res[i] = v ^ (v >> 1)
        return bytes(res)
    elif op == 6:
        for i in range(l):
            v = arr[i]
            res[i] = ((v << 2) | (v >> 6)) & 0xFF
        return bytes(res)
    elif op == 7:
        for i in range(l):
            res[i] = (arr[i] + i) & 0xFF
        return bytes(res)
    elif op == 8:
        for i in range(l):
            res[i] = (arr[i] * 7) & 0xFF
        return bytes(res)
    elif op == 9:
        acc = 0
        for i in range(l):
            acc ^= arr[i]
            res[i] = acc & 0xFF
        return bytes(res)
    elif op == 10:
        for i in range(l):
            res[i] = arr[(i + 2) % l]
        return bytes(res)
    elif op == 11:
        for i in range(l):
            res[i] = (arr[i] * 3) & 0xFF
        return bytes(res)
    elif op == 12:
        for i in range(l):
            res[i] = ((arr[i] * 3) + i) & 0xFF
        return bytes(res)
    elif op == 13:
        for i in range(l):
            v = arr[l - 1 - i]
            res[i] = ((v << 1) | (v >> 7)) & 0xFF
        return bytes(res)
    elif op == 14:
        idx = 0
        for i in range(0, l, 2):
            res[idx] = arr[i]
            idx += 1
        for i in range(1, l, 2):
            res[idx] = arr[i]
            idx += 1
        return bytes(res)
    elif op == 15:
        for i in range(l):
            res[i] = arr[(i + 1) % l]
        return bytes(res)
    elif op == 16:
        if l > 0:
            res[0] = arr[0]
        for i in range(1, l):
            res[i] = (arr[i] + arr[i - 1]) & 0xFF
        return bytes(res)
    elif op == 17:
        acc = 0
        for i in range(l):
            acc = (acc + arr[i]) & 0xFF
            res[i] = acc
        return bytes(res)
    else:
        raise ValueError(f"Unknown operation: {op}")

# ==============================================================================
# 3. Z3 INVERSION SOLVERS (Password & Flag Decryption)
# ==============================================================================

def apply_op_5bit_z3(op: int, arr: list[z3.BitVecRef]) -> tuple[list[z3.BitVecRef], list[z3.BoolRef]]:
    l = len(arr)
    res = [z3.BitVec(f"v5_{op}_{i}_{id(arr)}", 5) for i in range(l)]
    constraints = []

    if op == 0:
        for i in range(l):
            constraints.append(res[i] == arr[i])
    elif op == 1:
        for i in range(l):
            constraints.append(res[i] == arr[l - 1 - i])
    elif op == 2:
        for i in range(l):
            constraints.append(res[i] == ~arr[i])
    elif op == 3:
        for i in range(l):
            b0 = z3.Extract(0, 0, arr[i])
            b1 = z3.Extract(1, 1, arr[i])
            b2 = z3.Extract(2, 2, arr[i])
            b3 = z3.Extract(3, 3, arr[i])
            b4 = z3.Extract(4, 4, arr[i])
            constraints.append(res[i] == z3.Concat(b0, b1, b2, b3, b4))
    elif op == 4:
        for i in range(l):
            constraints.append(res[i] == (arr[i] ^ z3.LShR(arr[i], 1)))
    elif op == 5:
        for i in range(l):
            b_top = z3.Extract(4, 4, arr[i])
            b_low = z3.Extract(3, 0, arr[i])
            constraints.append(res[i] == z3.Concat(b_low, b_top))
    elif op == 6:
        for i in range(l):
            b_top = z3.Extract(4, 3, arr[i])
            b_low = z3.Extract(2, 0, arr[i])
            constraints.append(res[i] == z3.Concat(b_low, b_top))
    elif op == 7:
        for i in range(l):
            constraints.append(res[i] == arr[i] + i)
    elif op == 8:
        for i in range(l):
            constraints.append(res[i] == arr[i] * 7)
    elif op == 9:
        for i in range(l):
            constraints.append(res[i] == arr[i] * 3)
    elif op == 10:
        for i in range(l):
            if i == 0:
                constraints.append(res[0] == arr[0])
            else:
                constraints.append(res[i] == (res[i - 1] ^ arr[i]))
    elif op == 11:
        for i in range(l):
            constraints.append(res[i] == arr[(i + 2) % l])
    elif op == 12:
        for i in range(l):
            if i == 0:
                constraints.append(res[0] == arr[0])
            else:
                constraints.append(res[i] == res[i - 1] + arr[i])
    elif op == 13:
        constraints.append(res[0] == arr[0])
        for i in range(1, l):
            constraints.append(res[i] == arr[i] + arr[i - 1])
    elif op == 14:
        for i in range(l):
            constraints.append(res[i] == arr[i] * 3 + i)
    elif op == 15:
        for i in range(l):
            rev = arr[l - 1 - i]
            b_top = z3.Extract(4, 4, rev)
            b_low = z3.Extract(3, 0, rev)
            constraints.append(res[i] == z3.Concat(b_low, b_top))
    elif op == 16:
        idx = 0
        for i in range(0, l, 2):
            constraints.append(res[idx] == arr[i])
            idx += 1
        for i in range(1, l, 2):
            constraints.append(res[idx] == arr[i])
            idx += 1
    elif op == 17:
        for i in range(l):
            constraints.append(res[i] == arr[(i + 1) % l])
    else:
        raise ValueError(f"Unknown 5-bit op: {op}")

    return res, constraints

def solve_admin_password(u: list[int], y: list[int], x: int) -> str:
    """Solves for the 16-character admin password matching y under transform pipeline u."""
    s = z3.Solver()
    input_vars = [z3.BitVec(f"inp_{i}", 5) for i in range(16)]

    curr = input_vars
    for op in u:
        curr, cons = apply_op_5bit_z3(op, curr)
        for c in cons:
            s.add(c)

    for i in range(16):
        s.add(curr[i] == y[i])

    if s.check() == z3.sat:
        m = s.model()
        inp_vals = [m[input_vars[i]].as_long() for i in range(16)]
        alphabet = get_alphabet(x)
        pw = "".join(alphabet[v] for v in inp_vals)
        return pw
    else:
        raise RuntimeError("Failed to solve admin password: SAT constraints unsatisfiable!")

def apply_op_byte_z3(op: int, arr: list[z3.BitVecRef]) -> tuple[list[z3.BitVecRef], list[z3.BoolRef]]:
    l = len(arr)
    res = [z3.BitVec(f"vb_{op}_{i}_{id(arr)}", 8) for i in range(l)]
    constraints = []

    if op == 0:
        for i in range(l):
            constraints.append(res[i] == arr[i])
    elif op == 1:
        for i in range(l):
            constraints.append(res[i] == arr[l - 1 - i])
    elif op == 2:
        for i in range(l):
            constraints.append(res[i] == ~arr[i])
    elif op == 3:
        for i in range(l):
            b0 = z3.Extract(0, 0, arr[i])
            b1 = z3.Extract(1, 1, arr[i])
            b2 = z3.Extract(2, 2, arr[i])
            b3 = z3.Extract(3, 3, arr[i])
            b4 = z3.Extract(4, 4, arr[i])
            b5 = z3.Extract(5, 5, arr[i])
            b6 = z3.Extract(6, 6, arr[i])
            b7 = z3.Extract(7, 7, arr[i])
            constraints.append(res[i] == z3.Concat(b0, b1, b2, b3, b4, b5, b6, b7))
    elif op == 4:
        for i in range(l):
            b_top = z3.Extract(7, 5, arr[i])
            b_low = z3.Extract(4, 0, arr[i])
            constraints.append(res[i] == z3.Concat(b_low, b_top))
    elif op == 5:
        for i in range(l):
            constraints.append(res[i] == (arr[i] ^ z3.LShR(arr[i], 1)))
    elif op == 6:
        for i in range(l):
            b_top = z3.Extract(7, 6, arr[i])
            b_low = z3.Extract(5, 0, arr[i])
            constraints.append(res[i] == z3.Concat(b_low, b_top))
    elif op == 7:
        for i in range(l):
            constraints.append(res[i] == arr[i] + i)
    elif op == 8:
        for i in range(l):
            constraints.append(res[i] == arr[i] * 7)
    elif op == 9:
        for i in range(l):
            if i == 0:
                constraints.append(res[0] == arr[0])
            else:
                constraints.append(res[i] == (res[i - 1] ^ arr[i]))
    elif op == 10:
        for i in range(l):
            constraints.append(res[i] == arr[(i + 2) % l])
    elif op == 11:
        for i in range(l):
            constraints.append(res[i] == arr[i] * 3)
    elif op == 12:
        for i in range(l):
            constraints.append(res[i] == arr[i] * 3 + i)
    elif op == 13:
        for i in range(l):
            rev = arr[l - 1 - i]
            b_top = z3.Extract(7, 7, rev)
            b_low = z3.Extract(6, 0, rev)
            constraints.append(res[i] == z3.Concat(b_low, b_top))
    elif op == 14:
        idx = 0
        for i in range(0, l, 2):
            constraints.append(res[idx] == arr[i])
            idx += 1
        for i in range(1, l, 2):
            constraints.append(res[idx] == arr[i])
            idx += 1
    elif op == 15:
        for i in range(l):
            constraints.append(res[i] == arr[(i + 1) % l])
    elif op == 16:
        constraints.append(res[0] == arr[0])
        for i in range(1, l):
            constraints.append(res[i] == arr[i] + arr[i - 1])
    elif op == 17:
        for i in range(l):
            if i == 0:
                constraints.append(res[0] == arr[0])
            else:
                constraints.append(res[i] == res[i - 1] + arr[i])
    else:
        raise ValueError(f"Unknown byte op: {op}")

    return res, constraints

def decrypt_sealed_flag(u: list[int], hex_str: str) -> str:
    """Inverts the transformation pipeline on sealed archive hex to recover plaintext flag."""
    target_bytes = bytes.fromhex(hex_str.strip())
    l = len(target_bytes)

    s = z3.Solver()
    input_vars = [z3.BitVec(f"finp_{i}", 8) for i in range(l)]

    curr = input_vars
    for op in u:
        curr, cons = apply_op_byte_z3(op, curr)
        for c in cons:
            s.add(c)

    for i in range(l):
        s.add(curr[i] == target_bytes[i])

    if s.check() == z3.sat:
        m = s.model()
        recovered = bytes([m[input_vars[i]].as_long() for i in range(l)])
        return recovered.decode("utf-8", errors="replace")
    else:
        raise RuntimeError("Failed to decrypt flag: SAT constraints unsatisfiable!")

# ==============================================================================
# 4. FULL STATE DERIVATION (From 9 Guild Blocks or Seed)
# ==============================================================================

def compute_guild_state(blocks: list[bytes], g: int, h: int) -> dict:
    """
    Given the 9 exposed guild blocks:
      block 0: h (level, 4 bytes)
      block 1: g (coins, 4 bytes)
      block 2: battle_sigil(p) (4 bytes)
      block 3: archive_sigil(p) (6 bytes)
      block 4: battle_sigil(q) (4 bytes)
      block 5: export_sigil(q) (6 bytes)
      block 6: battle_sigil(r) (4 bytes)
      block 7: archive_sigil(r) (6 bytes)
      block 8: s (total monster coin sum, 4 bytes)
    Computes u, w, x, y and solves the admin password.
    """
    A_30 = 17643225600
    A_31 = 362880
    A_32 = 32

    concat_all = b"".join(blocks)
    t = to_pos_i64(sha256(concat_all)) % A_30
    u = lehmer_select(t, 18, 9)

    v = to_pos_i64(sha256(to_i32_bytes(g) + to_i32_bytes(h))) % A_31
    w = lehmer_select(v, 9, 9)

    x = t % A_32

    permuted_blocks = [blocks[w[i]] for i in range(9)]

    acc = sha256(transform_bytes_forward(u[0], permuted_blocks[0]))
    for i in range(1, 9):
        transformed = transform_bytes_forward(u[i], permuted_blocks[i])
        acc = sha256(acc + transformed)

    y = bytes_to_5bit_ints(acc, 16)
    password = solve_admin_password(u, y, x)

    return {
        "t": t, "u": u, "v": v, "w": w, "x": x, "y": y,
        "password": password
    }

def solve_from_seed(seed: str, flag: str = None) -> dict:
    """Computes full guild state directly from BURHAN_SEED."""
    p = PEngine(seed)
    A_29 = 4896

    g = p.int_range("coins", 1000, 9999)
    h = p.int_range("level", 8, 16)

    monsters = [p.int_range(f"mcoin{idx}", 120, 980) for idx in range(18)]

    n_seed = to_pos_i64(sha256(to_i32_bytes(h) + to_i32_bytes(g))) % A_29
    o = lehmer_select(n_seed, 18, 3)

    p_tag = f"Q{o[0] + 1}"
    q_tag = f"{p_tag}>Q{o[1] + 1}"
    r_tag = f"{q_tag}>Q{o[2] + 1}"

    s = g + monsters[o[0]] + monsters[o[1]] + monsters[o[2]]

    blocks = [
        to_i32_bytes(h),
        to_i32_bytes(g),
        to_i32_bytes(p.int_range(f"battle:{p_tag}", 10000, 99999)),
        bytes.fromhex(p.hex_sigil(f"archive:{p_tag}", 6)),
        to_i32_bytes(p.int_range(f"battle:{q_tag}", 10000, 99999)),
        bytes.fromhex(p.hex_sigil(f"export:{q_tag}", 6)),
        to_i32_bytes(p.int_range(f"battle:{r_tag}", 10000, 99999)),
        bytes.fromhex(p.hex_sigil(f"archive:{r_tag}", 6)),
        to_i32_bytes(s)
    ]

    state = compute_guild_state(blocks, g, h)
    state.update({
        "seed": seed, "g": g, "h": h, "o": o,
        "p_tag": p_tag, "q_tag": q_tag, "r_tag": r_tag,
        "s": s, "blocks": blocks
    })

    if flag:
        raw = flag.encode("utf-8")
        for op in state["u"]:
            raw = transform_bytes_forward(op, raw)
        hex_ciphertext = raw.hex()
        state["encrypted_flag_hex"] = hex_ciphertext
        state["decrypted_flag"] = decrypt_sealed_flag(state["u"], hex_ciphertext)

    return state


# ==============================================================================
# 5. LIVE REMOTE SOLVER (token-authenticated BurhanQuest protocol)
# ==============================================================================

def live_solve(host, port, token, log_path=None):
    import time
    log = open(log_path, "w") if log_path else None
    s = socket.create_connection((host, int(port)), timeout=15)
    buf = {"v": ""}
    def pump(t=3.0):
        s.settimeout(t); end=time.time()+t; out=b""
        while time.time()<end:
            try:
                d=s.recv(4096)
                if not d: break
                out+=d; end=time.time()+0.5
            except socket.timeout: break
        txt=out.decode("utf-8","replace"); buf["v"]+=txt
        if log: log.write(txt); log.flush()
        return txt
    def read_until(exp, t=15):
        end=time.time()+t
        while exp not in buf["v"] and time.time()<end:
            pump(1.0)
        i=buf["v"].find(exp)
        if i!=-1:
            r=buf["v"][:i+len(exp)]; buf["v"]=buf["v"][i+len(exp):]; return r
        r=buf["v"]; buf["v"]=""; return r
    def send(x):
        if log: log.write("\n>>>SEND: %s\n"%x); log.flush()
        s.sendall((x+"\n").encode())

    read_until("CTFd access token: "); send(token)
    read_until("Masukkan pilihan: "); send("1")
    read_until("Masukkan username: "); send("frieren")
    read_until("Masukkan password: "); send("frieren")
    read_until("Masukkan pilihan: "); send("1")
    prof=read_until("Masukkan pilihan: ")
    h=int(re.search(r"Level Pengembara:\s*(\d+)",prof).group(1))
    g=int(re.search(r"Koin Didapatkan:\s*(\d+)",prof).group(1))
    print("[+] h(level)=%d g(coins)=%d"%(h,g))

    A_29=4896
    n_seed=to_pos_i64(sha256(to_i32_bytes(h)+to_i32_bytes(g)))%A_29
    o=lehmer_select(n_seed,18,3)
    p_id,q_id,r_id=("Q%d"%(o[0]+1),"Q%d"%(o[1]+1),"Q%d"%(o[2]+1))
    print("[+] quest chain: %s -> %s -> %s"%(p_id,q_id,r_id))

    def do_quest(qid):
        send("5"); read_until("Masukkan ID Quest yang ingin diambil"); send(qid)
        out=read_until("Masukkan pilihan: ",t=20)
        bs=int(re.search(r"sigil-pertempuran\s*\[(.*?)\]:\s*(\d+)",out).group(2))
        coin=int(re.search(r"mendapatkan\s+\d+\s+exp dan\s+(\d+)\s+koin",out).group(1))
        return bs,coin
    bsp,c1=do_quest(p_id); send("7"); bb1=read_until("Masukkan pilihan: ")
    arch_p=re.search(r"sigil-arsip:\s*([0-9a-fA-F]+)",bb1).group(1)
    bsq,c2=do_quest(q_id); send("6"); ex1=read_until("Masukkan pilihan: ")
    exp_q=re.search(r"sigil-ekspor:\s*([0-9a-fA-F]+)",ex1).group(1)
    bsr,c3=do_quest(r_id); send("7"); bb2=read_until("Masukkan pilihan: ")
    arch_r=re.search(r"sigil-arsip:\s*([0-9a-fA-F]+)",bb2).group(1)

    s_coin=g+c1+c2+c3
    blocks=[to_i32_bytes(h),to_i32_bytes(g),to_i32_bytes(bsp),bytes.fromhex(arch_p[:12]),
            to_i32_bytes(bsq),bytes.fromhex(exp_q[:12]),to_i32_bytes(bsr),
            bytes.fromhex(arch_r[:12]),to_i32_bytes(s_coin)]
    state=compute_guild_state(blocks,g,h)
    pw=state["password"]
    print("[+] recovered admin password: %s"%pw)

    send("0"); read_until("Masukkan pilihan: ")
    send("1"); read_until("Masukkan username: "); send("burhan")
    read_until("Masukkan password: "); send(pw)
    admin=read_until("Masukkan pilihan: ",t=10)
    if "Selamat datang, Burhan" not in admin:
        raise RuntimeError("admin login failed:\n"+admin[-400:])
    print("[+] admin login OK (Selamat datang, Burhan)")
    send("13"); arch=pump(5)
    ch=re.search(r"([0-9a-fA-F]{30,})",arch).group(1)
    flag=decrypt_sealed_flag(state["u"],ch)
    print("[+] FLAG: %s"%flag)
    s.close()
    if log: log.close()
    return flag


def main():
    if len(sys.argv) >= 3:
        host=sys.argv[1]; port=int(sys.argv[2])
        token=sys.argv[3] if len(sys.argv)>3 else os.environ.get("CTFD_TOKEN")
        if not token:
            raise SystemExit("set CTFD_TOKEN or pass it as the third argument")
        flag=live_solve(host,port,token,log_path="live_transcript.log")
        print("\nFinal Flag: %s"%flag)
    else:
        print("Usage: python3 solve.py HOST PORT [CTFD_TOKEN]")
        print("NOTE: flag_mode=random -> each instance yields a different suffix.")

if __name__ == "__main__":
    main()

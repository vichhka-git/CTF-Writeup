#!/usr/bin/env python3
import ctypes
import os
import re
import socket
import sys
from hashlib import shake_256
from pathlib import Path

SO_PATH = Path(__file__).parent / "solver_assets" / "libsearch.so"
libsearch = ctypes.CDLL(str(SO_PATH))
libsearch.find_matching_x.argtypes = [
    ctypes.c_uint64,
    ctypes.c_uint64,
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_uint64,
]
libsearch.find_matching_x.restype = ctypes.c_uint64

MASK64 = (1 << 64) - 1

def recv_until(sock, suffix):
    data = b""
    while not data.endswith(suffix):
        chunk = sock.recv(1)
        if not chunk:
            raise EOFError(f"Connection closed while waiting for {suffix}. Received so far: {data}")
        data += chunk
    return data

def solve_polly(host, port):
    print(f"[*] Connecting to {host}:{port}...")
    s = socket.create_connection((host, port), timeout=15)

    # Read until the banner ending: "\n\n"
    banner_bytes = recv_until(s, b"perhaps theirs a way to decrypt it??\n\n")
    banner = banner_bytes.decode("utf-8", errors="replace")
    print(f"[*] Banner: {banner.strip()}")

    m = re.search(r"The encrypted flag is ([0-9a-fA-F]+), the nonce is ([0-9a-fA-F]+)", banner)
    if not m:
        raise ValueError(f"Could not parse banner: {banner}")

    orig_ciphertext = bytes.fromhex(m.group(1))
    orig_nonce = bytes.fromhex(m.group(2))
    print(f"[*] Orig ciphertext len: {len(orig_ciphertext)}")
    print(f"[*] Orig nonce: {orig_nonce.hex()}")

    base_nonce = orig_nonce[:9]
    target_suffix = int.from_bytes(orig_nonce[9:], "big")
    print(f"[*] Target suffix (lower 24 bits): {target_suffix:#08x}")

    # Derive shifts and num
    material = shake_256(base_nonce).digest(5)
    available_shifts = list(range(1, 64))
    shifts = []
    for byte in material[1:]:
        index = byte % len(available_shifts)
        shifts.append(available_shifts.pop(index))
    num = material[0] & 1

    print(f"[*] Shifts: {shifts}, num: {num}")

    def transform(state):
        if num % 2 == 0:
            state ^= (state << shifts[0]) & MASK64
            state ^= state >> shifts[1]
            state ^= (state << shifts[2]) & MASK64
            state ^= state >> shifts[3]
        else:
            state ^= (state >> shifts[0])
            state ^= (state << shifts[1]) & MASK64
            state ^= (state >> shifts[2])
            state ^= (state << shifts[3]) & MASK64
        return state & MASK64

    def transformation(operator, state):
        result = 0
        for bit in range(64):
            if state & (1 << bit):
                result ^= operator[bit]
        return result & MASK64

    def square_operator(operator):
        return [transformation(operator, column) for column in operator]

    first_jump = [transform(1 << bit) for bit in range(64)]
    jumps = [first_jump]
    for _ in range(63):
        jumps.append(square_operator(jumps[-1]))

    def state_at(x, seed):
        state = seed & MASK64
        for bit in range(64):
            if x & (1 << bit):
                state = transformation(jumps[bit], state)
        return state

    # Step 1: Collect linear equations to recover seed
    print("[*] Collecting GF(2) linear equations from oracle...")
    basis = []
    def add_vector(v):
        for b in basis:
            v = min(v, v ^ b)
        if v > 0:
            basis.append(v)
            basis.sort(reverse=True)
            return True
        return False

    M_rows = []
    T_rows = []
    x = 0

    while len(M_rows) < 64:
        recv_until(s, b"which seed modifier would you like to use?\n")
        s.sendall(f"{x}\n".encode())

        recv_until(s, b"enter a string to be encrypted: ")
        s.sendall(b"a\n")

        line1 = recv_until(s, b"\n").decode().strip()
        line2 = recv_until(s, b"\n").decode().strip()

        nonce_byte_m = re.search(r"Your nonce byte is:\s*([0-9a-fA-F]{2})", line2)
        if not nonce_byte_m:
            raise ValueError(f"Unexpected response: {line1} / {line2}")
        leak_byte = int(nonce_byte_m.group(1), 16)

        for bit_idx in range(8):
            v = 0
            for i in range(64):
                val = (state_at(x, 1 << i) >> bit_idx) & 1
                v |= (val << i)
            if add_vector(v):
                row = [(v >> i) & 1 for i in range(64)]
                M_rows.append(row)
                T_rows.append((leak_byte >> bit_idx) & 1)
                if len(M_rows) == 64:
                    break
        x += 1
        if x > 30 and len(M_rows) < 64:
            print(f"[-] Warning: after 30 queries rank is {len(M_rows)}")
            if len(M_rows) < 64 and x > 50:
                raise RuntimeError(f"Could not reach full rank: {len(M_rows)}/64")

    print(f"[+] Reached full rank 64 with {x} oracle queries!")

    # Gaussian elimination
    M = [r[:] for r in M_rows]
    T = T_rows[:]
    for col in range(64):
        pivot = None
        for r in range(col, 64):
            if M[r][col] == 1:
                pivot = r
                break
        assert pivot is not None, f"No pivot at col {col}"
        M[col], M[pivot] = M[pivot], M[col]
        T[col], T[pivot] = T[pivot], T[col]
        for r in range(64):
            if r != col and M[r][col] == 1:
                for c in range(64):
                    M[r][c] ^= M[col][c]
                T[r] ^= T[col]

    seed = 0
    for col in range(64):
        if T[col] == 1:
            seed |= (1 << col)
    print(f"[+] Recovered seed: {seed:#018x}")

    # Step 2: C search for matching x
    print(f"[*] Searching for x such that state_at(x, seed) & 0xFFFFFF == {target_suffix:#08x}...")
    max_steps = 100_000_000
    found_x = libsearch.find_matching_x(
        seed,
        target_suffix,
        shifts[0],
        shifts[1],
        shifts[2],
        shifts[3],
        num,
        max_steps,
    )
    if found_x == 0xFFFFFFFFFFFFFFFF:
        raise RuntimeError("Matching x not found within max_steps!")
    print(f"[+] Found matching x = {found_x}!")

    # Step 3: Query oracle with found_x and all-zero plaintext
    recv_until(s, b"which seed modifier would you like to use?\n")
    s.sendall(f"{found_x}\n".encode())

    recv_until(s, b"enter a string to be encrypted: ")
    # Send all-zero plaintext of exact ciphertext length
    s.sendall(b"\x00" * len(orig_ciphertext) + b"\n")

    line1 = recv_until(s, b"\n").decode().strip()
    line2 = recv_until(s, b"\n").decode().strip()

    ct_m = re.search(r"Your ciphertext is:\s*([0-9a-fA-F]+)", line1)
    if not ct_m:
        raise ValueError(f"Could not parse ciphertext: {line1}")
    keystream = bytes.fromhex(ct_m.group(1))

    # Step 4: Recover flag
    flag = bytes([c ^ k for c, k in zip(orig_ciphertext, keystream)])
    flag_str = flag.decode('utf-8', errors='replace')
    print(f"\n" + "=" * 50)
    print(f"[+] FLAG: {flag_str}")
    print("=" * 50 + "\n")
    s.close()
    return flag_str

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5000
    flag = solve_polly(host, port)

#!/usr/bin/env python3
"""
PoC: Model E1337 v2 - Hardened Rolling Code Lock (HackerOne CTF)
Solves the rolling code by recovering the PRNG state via Gaussian elimination over GF(2).

Usage: python3 solve.py https://<instance>.ctf.hacker101.com/
"""

import sys
import re
import numpy as np
import requests

# Globals
fullOp3 = None     # 3x transformation matrix (for v2)
ret_mat = None     # augmented matrix for solving

def next_code(state, bits):
    """Pure function: generate 'bits' output bits from given state, return (code, new_state)."""
    ret = 0
    for i in range(bits):
        ret <<= 1
        ret |= state & 1
        for k in range(3):
            state = (state << 1) ^ (state >> 61)
            state &= 0xFFFFFFFFFFFFFFFF
            for j in range(0, 64, 4):
                cur = (state >> j) & 0xF
                cur = (cur >> 3) | ((cur >> 2) & 2) | ((cur << 3) & 8) | ((cur << 2) & 4)
                state ^= cur << j
    return ret, state

def build_matrices():
    """Build the transformation matrices for the PRNG (Frederick Altrock's construction)."""
    global fullOp3

    # op1: state << 1
    op1 = np.zeros([64, 64], dtype=int)
    for i in range(63):
        op1[i, i + 1] = 1

    # op2: state >> 61
    op2 = np.zeros([64, 64], dtype=int)
    for i in range(61, 64):
        op2[i, i - 61] = 1

    # M_shift = (state << 1) ^ (state >> 61)
    M_shift = np.mod(op1 + op2, 2)

    # (I+P) matrix: state ^= nibble_permute(state)
    # Each nibble transformation: (A,B,C,D) -> (A^D, B^D, C^A, D^A)
    submatrix = np.array([
        [1, 0, 0, 1],
        [0, 1, 0, 1],
        [1, 0, 1, 0],
        [1, 0, 0, 1],
    ])
    I_plus_P = np.zeros([64, 64], dtype=int)
    for i in range(0, 64, 4):
        I_plus_P[i:i+4, i:i+4] = submatrix

    # F = (I+P) * M_shift  (single state transformation, XOR flip cancels)
    fullOp = np.mod(np.matmul(I_plus_P, M_shift), 2)

    # v2: 3 transformations per output bit
    fullOp3 = np.mod(np.linalg.matrix_power(fullOp, 3), 2)

def build_ret_matrix():
    """Build 64x65 augmented matrix: 16 nibble constraints + 48 code equations."""
    global ret_mat
    ret_mat = np.zeros([64, 65], dtype=int)

    # First 16 rows: nibble bit equality (9 = 1001, bits 0 and 3 equal per nibble)
    for i in range(16):
        val = 9 << (4 * i)
        ret_mat[i, :64] = [int(b) for b in f'{val:064b}']

    # Next 48 rows: LSB of state after 1..48 F^3 transformations
    cur = np.identity(64, dtype=int)
    for i in range(48):
        ret_mat[16 + i, :64] = cur[63, :]  # row 63 = LSB
        cur = np.mod(np.matmul(cur, fullOp3), 2)

def vec_to_int(vec):
    """Convert bit vector (MSB first) to integer."""
    v = 0
    for i in range(64):
        if vec[i]:
            v |= 1 << (63 - i)
    return v

def gauss_elim_over_gf2(aug_mat):
    """Gaussian elimination over GF(2). Returns solution vector (MSB first)."""
    aug = aug_mat.copy()
    n = 64

    # Forward elimination
    for col in range(n):
        pivot = None
        for r in range(col, aug.shape[0]):
            if aug[r, col] == 1:
                pivot = r
                break
        if pivot is None:
            continue
        aug[[col, pivot]] = aug[[pivot, col]]
        for r in range(col + 1, aug.shape[0]):
            if aug[r, col] == 1:
                aug[r] = aug[r] ^ aug[col]

    # Back substitution
    aug = aug[:n]
    for col in range(n - 1, -1, -1):
        for r in range(col):
            if aug[r, col] == 1:
                aug[r] = aug[r] ^ aug[col]

    return aug[:, 64]


def solve(url):
    base_url = url.rstrip('/')

    print("[*] Building transformation matrices...")
    build_matrices()
    build_ret_matrix()

    print("[*] Fetching one code from server...")
    r = requests.post(f'{base_url}/unlock', data={'code': '0'})
    code = int(re.findall(r'(\d+)', r.text)[0])
    print(f"[+] Got code: {code}")

    # Build RHS: 16 zeros (constraints) + 48 MSB of code
    code_bin = f'{code:064b}'
    rhs = [0] * 16 + [int(b) for b in code_bin[:48]]
    ret_mat[:, 64] = rhs

    print("[*] Solving system via Gaussian elimination over GF(2)...")
    state_bits = gauss_elim_over_gf2(ret_mat)
    recovered_state = vec_to_int(state_bits)
    print(f"[+] Recovered state: {recovered_state:064b}")

    # Predict: skip past the code we already saw, then predict the next one
    _, state = next_code(recovered_state, 64)   # skip first code
    predicted, _ = next_code(state, 64)          # this is what server expects next
    print(f"[+] Predicted next code: {predicted}")

    print("[*] Submitting predicted code...")
    r = requests.post(f'{base_url}/unlock', data={'code': str(predicted)})
    print(f"[+] Response: {r.text}")

    # Extract flag
    flag_match = re.search(r'\^FLAG\^([a-f0-9]+)\$FLAG\$', r.text)
    if flag_match:
        flag = flag_match.group(1)
        print(f"\n[!!!] FLAG: {flag}")
        return flag

    return r.text


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <ctf_base_url>")
        sys.exit(1)
    solve(sys.argv[1])

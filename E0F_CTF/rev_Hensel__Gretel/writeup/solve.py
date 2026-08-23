import struct
A = [
    0x5820df5da1121b28,
    0x1ea66af9af7e804,
    0x70b4cf15c16e7160,
    0x4f8272c706163f0e,
    0x80ccc908b6dcfeda,
    0xa7a4684b78867cb
]

# Read output of my solve_full_3.py (which I can just import or parse, but I already have the output from the last run)
# Wait, I'll just re-run the whole solver, then XOR!
import struct
import sys

def murmur_mix(v):
    v = v & 0xffffffffffffffff
    v ^= (v >> 30)
    v = (v * 0xbf58476d1ce4e5b9) & 0xffffffffffffffff
    v ^= (v >> 27)
    v = (v * 0x94d049bb133111eb) & 0xffffffffffffffff
    v ^= (v >> 31)
    return v

instructions = []

for loop in range(17):
    # Op 0 loop
    for uVar5 in range(6):
        v = (uVar5 * 0x10101 ^ (loop << 32) ^ 0x68336e73336c2132) + 0x9e3779b97f4a7c15
        k = murmur_mix(v)
        instructions.append((0, uVar5, k))

    # Op 1 loop
    for uVar4 in range(6):
        rot = (uVar4 * 3 + loop * 7) % 0x3f + 1
        instructions.append((1, uVar4, rot))

    # Op 2 and 3 loop
    for uVar5 in range(6):
        v = (uVar5 * 0x9e37 + 0x66ae82cb2b69d47 + loop * 0x100000001b3) & 0xffffffffffffffff
        raw_k2 = murmur_mix(v)
        k2 = raw_k2 | 1
        instructions.append((2, uVar5, k2))
        
        v3 = (raw_k2 ^ 0xa5a5a5a5a5a5a5a5) + 0x9e3779b97f4a7c15
        v3 = v3 & 0xffffffffffffffff
        k3 = murmur_mix(v3)
        instructions.append((3, uVar5, k3))

    # Op 4
    shift = (loop * 5 + 1) % 6
    instructions.append((4, 0, shift))

def f(x):
    return (4 * x**3 + 2 * x**2 + x) & 0xffffffffffffffff

def invert_op0(y, k):
    a = y & 1
    for i in range(1, 64):
        val = f(a)
        diff = (y - val) & ((1 << (i + 1)) - 1)
        b = (diff >> i) & 1
        a = a | (b << i)
    return a ^ k

def invert_op1(A, idx, rot):
    v = A[(idx + 5) % 6]
    rol_v = ((v << rot) | (v >> (64 - rot))) & 0xffffffffffffffff
    A[idx] = (A[idx] - rol_v) & 0xffffffffffffffff

def modinv(a, m):
    m0 = m
    y = 0
    x = 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        t = m
        m = a % m
        a = t
        t = y
        y = x - q * y
        x = t
    if x < 0:
        x = x + m0
    return x

A = [
    0x5820df5da1121b28,
    0x1ea66af9af7e804,
    0x70b4cf15c16e7160,
    0x4f8272c706163f0e,
    0x80ccc908b6dcfeda,
    0xa7a4684b78867cb
]

for op in reversed(instructions):
    opcode, idx, val = op
    if opcode == 0:
        A[idx] = invert_op0(A[idx], val)
    elif opcode == 1:
        invert_op1(A, idx, val)
    elif opcode == 2:
        A[idx] = (A[idx] * modinv(val, 2**64)) & 0xffffffffffffffff
    elif opcode == 3:
        A[idx] = (A[idx] - val) & 0xffffffffffffffff
    elif opcode == 4:
        new_A = [0] * 6
        for i in range(6):
            new_A[i] = A[(i + val) % 6]
        A = new_A

out = b""
for x in A:
    out += struct.pack("<Q", x)

print(out)

# XOR with constants
xors = [
    0x771c23d4baf19e05,
    0x2d891be6035ac74f,
    0xc441907ae82f6b13,
    0x0f56d2a9bc7341e8,
    0x9ab308e175c64fd2,
    0x43e7c0198d2ab56f
]

flag = b""
for i in range(6):
    val = A[i] ^ xors[i]
    flag += struct.pack("<Q", val)

print(flag)

#!/usr/bin/env python3
import pefile

pe = pefile.PE('../bit-garden.exe')

def get_bytes(va, length):
    rva = va - pe.OPTIONAL_HEADER.ImageBase
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
            offset = rva - s.VirtualAddress
            return s.get_data()[offset:offset+length]
    return b''

r9 = 0xbf58476d1ce4e5b9
r10 = 0x9e3779b97f4a7c15
r11 = 0x94d049bb133111eb

# 1. Recover S-box from .mazeA and .mazeB
mazeA = get_bytes(0x140007000, 16)
mazeB = get_bytes(0x140008000, 16)
sbox = [a ^ b for a, b in zip(mazeA, mazeB)]
inv_sbox = [0] * 16
for i, v in enumerate(sbox):
    inv_sbox[v] = i

# 2. Compute round keys for 56 rounds
round_keys = []
rcx = 0xb98ec20eeb6f188
for r in range(56):
    state = rcx & 0xffffffffffffffff
    rbx = ((state ^ (state >> 30)) * r9) & 0xffffffffffffffff
    rdx = ((rbx ^ (rbx >> 27)) * r11) & 0xffffffffffffffff
    rdi = (rdx ^ (rdx >> 31)) & 0xffffffffffffffff
    
    k0 = (rdi >> 3) & 0xf
    k1 = (rdi >> 19) & 0xf
    k2 = ((rdx >> 37) & 3) + 1
    rot = k2 & 3
    
    rdi_shift = rdx >> 43
    k3 = ((rdi_shift % 3) - 1) & 0xf
    
    rdx_shift = rdx >> 51
    k4 = ((rdx_shift % 3) - 1) & 0xf
    
    round_keys.append((k0, k1, rot, k3, k4))
    rcx = (rcx + r10) & 0xffffffffffffffff

# 3. Compute expected target ciphertext
r8_data = get_bytes(0x1400040e0, 32)
prefix = b'e0f{'
val = (7 * prefix[0] + 3 * prefix[1] + 5 * prefix[2] + 9 * prefix[3]) & 3
ecx = (val + 1)
rcx = (ecx * r10) & 0xffffffffffffffff
rax = 0x243f6a8885a308d3 ^ rcx
rax = (rax + r10) & 0xffffffffffffffff

target = bytearray(32)
for rdi in range(32):
    rcx = rax
    rcx = ((rcx ^ (rcx >> 30)) * r9) & 0xffffffffffffffff
    rsi = ((rcx ^ (rcx >> 27)) * r11) & 0xffffffffffffffff
    rdx = (rsi ^ (rsi >> 31)) & 0xffffffffffffffff
    cl = (rdi * 8) & 0x38
    dl = (rdx >> cl) & 0xff
    target[rdi] = dl ^ r8_data[rdi]
    rax = (rax + r10) & 0xffffffffffffffff

# 4. Initialize 16x16 bit grid from target ciphertext
grid = [0] * 256
for rax in range(32):
    b = target[rax]
    for bit in range(8):
        grid[rax * 8 + bit] = (b >> bit) & 1

def rol4(v, r):
    r = r & 3
    return ((v << r) & 0xf) | (v >> ((4 - r) & 3))

def ror4(v, r):
    r = r & 3
    return (v >> r) | ((v << ((4 - r) & 3)) & 0xf)

# 5. Invert 56 rounds of Margolus block CA + 2D Toroidal Translation
for r in reversed(range(56)):
    k0, k1, rot, col_shift, row_shift = round_keys[r]
    
    # Invert 2D translation
    temp_grid = list(grid)
    for row_in in range(16):
        for col_in in range(16):
            row_out = (row_in - row_shift) & 0xf
            col_out = (col_in - col_shift) & 0xf
            grid[row_out * 16 + col_out] = temp_grid[row_in * 16 + col_in]
    
    # Invert 2x2 Margolus blocks
    block_offset = r & 1
    for row in range(block_offset, 16 + block_offset, 2):
        for col in range(block_offset, 16 + block_offset, 2):
            r0 = row & 0xf
            r1 = (row + 1) & 0xf
            c0 = col & 0xf
            c1 = (col + 1) & 0xf
            
            b0 = grid[r0 * 16 + c0]
            b1 = grid[r0 * 16 + c1]
            b2 = grid[r1 * 16 + c0]
            b3 = grid[r1 * 16 + c1]
            v = b0 | (b1 << 1) | (b2 << 2) | (b3 << 3)
            
            v = v ^ k1
            v = rol4(v, rot)
            v = inv_sbox[v]
            v = ror4(v, rot)
            v = v ^ k0
            
            grid[r0 * 16 + c0] = v & 1
            grid[r0 * 16 + c1] = (v >> 1) & 1
            grid[r1 * 16 + c0] = (v >> 2) & 1
            grid[r1 * 16 + c1] = (v >> 3) & 1

# 6. Invert 8-bit bit-reversal
def bit_reverse_8(n):
    b = '{:08b}'.format(n)
    return int(b[::-1], 2)

buffer = bytearray(32)
for bit_idx in range(256):
    rev_idx = bit_reverse_8(bit_idx)
    bit_val = grid[rev_idx]
    byte_idx = bit_idx // 8
    bit = bit_idx % 8
    buffer[byte_idx] |= (bit_val << bit)

# 7. Invert initial PRNG XOR and permutation
recovered_input = bytearray(32)
rdi_val = 0x12a6ec2ef2a9de7e
for i in range(32):
    state = rdi_val & 0xffffffffffffffff
    rbx = ((state ^ (state >> 30)) * r9) & 0xffffffffffffffff
    rdx = ((rbx ^ (rbx >> 27)) * r11) & 0xffffffffffffffff
    key_byte = (rdx >> 56) & 0xff
    idx = (5 + 13 * i) & 0x1f
    recovered_input[i] = buffer[idx] ^ key_byte
    rdi_val = (rdi_val + r10) & 0xffffffffffffffff

flag = (b'e0f{' + recovered_input + b'}').decode()
print(flag)

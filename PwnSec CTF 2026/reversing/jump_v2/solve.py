#!/usr/bin/env python3
import struct
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_PROT_ALL
from unicorn.x86_const import UC_X86_REG_XMM0, UC_X86_REG_XMM1

# --- Step 1: Exact Target Dwords ---
TARGET_DWORDS = [
    0x60f41764, 0xe255e6e8, 0xef382b52, 0x0196eb72,
    0xeb801996, 0xd7fdd154, 0x85c90023, 0xc5e6edc2,
    0x6d9fec2d, 0xa5ffccfb, 0x96c3ede9, 0x1b323cbe
]

# --- Step 2: Invert Stage 3 (0x49b666) ---
def bswap32(x):
    return int.from_bytes(x.to_bytes(4, 'little'), 'big')

def inv_xor_shift(y, cl):
    x = 0
    for i in range(0, 32, cl):
        x ^= (y >> i)
    return x

def inv_single(y, cl):
    y = bswap32(y)
    y = y ^ 0xa1b2c3d4
    y = inv_xor_shift(y, cl)
    return bswap32(y)

shifts = [8, 16, 24]
s2_out = [inv_single(TARGET_DWORDS[i], shifts[i % 3]) for i in range(12)]
print("Stage 2 out dwords:", [hex(x) for x in s2_out])

# --- Step 3: Invert Stage 2 (0x420e19) ---
ROUND_CONSTANTS = [
    (0x5cdf0d71, 0x6b4d0809, 0x1497712c),
    (0x761721,   0x3b3d70d,  0xf904c9),
    (0x43b1893,  0xc1072960, 0x330c256),
    (0x271c2df5, 0x94241560, 0x1e32763e),
    (0x11297387, 0x10b3134c, 0x53ef702),
    (0x505163d3, 0x6bacaa28, 0x8700f895),
    (0xbf05553,  0x9e28673,  0xc361fb10),
    (0x1066928c, 0x98e47ca7, 0x576970a7)
]

def ror32(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xffffffff

def rol32(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xffffffff

def step_bwd_stage2(new_s0, new_s1, new_s2, new_s3, c4, c5, c6):
    s0 = new_s2
    s1 = ((new_s0 ^ s0) - 2*c4) & 0xffffffff
    s2 = ((new_s3 ^ s1) - c5 - 1337) & 0xffffffff
    s3 = new_s1 ^ c6 ^ 1337 ^ s2
    return (s0, s1, s2, s3)

def inv_stage2_block(out_dwords):
    s0 = bswap32(rol32(out_dwords[0], 7))
    s1 = bswap32(rol32(out_dwords[1], 16))
    s2 = bswap32(rol32(out_dwords[2], 5))
    s3 = bswap32(rol32(out_dwords[3], 19))
    
    cur = (s0, s1, s2, s3)
    for c4, c5, c6 in reversed(ROUND_CONSTANTS):
        cur = step_bwd_stage2(*cur, c4, c5, c6)
    
    chunk_dwords = [bswap32(x) for x in cur]
    return struct.pack('<4I', *chunk_dwords)

interm_b0 = inv_stage2_block(s2_out[0:4])
interm_b1 = inv_stage2_block(s2_out[4:8])
interm_b2 = inv_stage2_block(s2_out[8:12])
interm_bytes = interm_b0 + interm_b1 + interm_b2
print("Intermediate bytes (48B):", interm_bytes.hex())

# --- Step 4: Invert Stage 1 (12-round Feistel over xmm0, xmm1, xmm2) ---
raw = open('child.elf', 'rb').read()
t1 = raw[0x145220:0x145220+192]
t2 = raw[0x145160:0x145160+192]
t3 = raw[0x1450a0:0x1450a0+192]
t4 = raw[0x1452e0:0x1452e0+192]

uc = Uc(UC_ARCH_X86, UC_MODE_64)
uc.mem_map(0x1000, 0x1000, UC_PROT_ALL)
code_bwd = bytes.fromhex('660fefc1660f38dbc0660fefc9660f38dfc1')
uc.mem_write(0x1100, code_bwd)

def inv_aesenc_fn(val16, rk16):
    uc.reg_write(UC_X86_REG_XMM0, int.from_bytes(val16, 'little'))
    uc.reg_write(UC_X86_REG_XMM1, int.from_bytes(rk16, 'little'))
    uc.emu_start(0x1100, 0x1100 + len(code_bwd))
    return uc.reg_read(UC_X86_REG_XMM0).to_bytes(16, 'little')

def pshufb_fn(val16, mask16):
    res = bytearray(16)
    for i in range(16):
        m = mask16[i]
        res[i] = val16[m & 15] if m < 128 else 0
    return bytes(res)

def inv_pshufb_fn(val16, mask16):
    inv_mask = bytearray(16)
    for i in range(16):
        inv_mask[mask16[i]] = i
    return pshufb_fn(val16, inv_mask)

def xor16(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def inv_stage1(x0, x1, x2):
    for r in reversed(range(12)):
        m1 = t1[r*16:(r+1)*16]
        k2 = t2[r*16:(r+1)*16]
        k3 = t3[r*16:(r+1)*16]
        m4 = t4[r*16:(r+1)*16]
        
        x3 = x2
        x2 = x1
        x1 = x0
        
        x4 = pshufb_fn(x2, m4)
        enc_target = xor16(xor16(x3, x1), x4)
        inner = inv_aesenc_fn(enc_target, k3)
        shuffled_x0 = xor16(inner, k2)
        x0 = inv_pshufb_fn(shuffled_x0, m1)
    return x0, x1, x2

p0, p1, p2 = inv_stage1(interm_b0, interm_b1, interm_b2)
child_placeholder = p0 + p1 + p2
print("Recovered child placeholder (48B):", child_placeholder.hex())

# --- Step 5: Recover raw input via ChaCha20 Keystream ---
ph_a = bytes.fromhex('7caf354b6d3f8b20785eac6813457435b63a704d5488b3109e4bc03bc3c45071feb5e2c78874b65abad16c277ef5828e')
KEYSTREAM = bytes(a ^ ord('A') for a in ph_a)

raw_input_bytes = bytes(c ^ k for c, k in zip(child_placeholder, KEYSTREAM))
print("Raw input bytes:", raw_input_bytes)
try:
    raw_input_str = raw_input_bytes.decode('utf-8')
    print("Raw input string:", repr(raw_input_str))
except Exception as e:
    print("Failed to decode utf-8:", e)

with open('solution.txt', 'wb') as f:
    f.write(raw_input_bytes)

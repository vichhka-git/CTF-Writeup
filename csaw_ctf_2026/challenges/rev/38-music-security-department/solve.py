#!/usr/bin/env python3
import os, sys, itertools, time

ROM_PATH = os.path.join(os.path.dirname(__file__), 'files/session.bin')

with open(ROM_PATH, 'rb') as f:
    rom = f.read()

INV_8D = 0x45
INV_4F = 0xaf

def inv_fwd(s):
    orig = [0] * 6
    for i in range(6):
        prev_a = s[i - 1] if i > 0 else 0
        orig[i] = (((s[i] - 0x3b) * INV_8D) ^ prev_a) & 0xff
    return orig

def inv_bwd(s):
    orig = [0] * 6
    for i in range(6):
        prev_a = s[5 - (i - 1)] if i > 0 else 0
        orig[5 - i] = (((s[5 - i] - 0xc7) * INV_4F) ^ prev_a) & 0xff
    return orig

def inv_key_sched(s):
    return inv_fwd(inv_bwd(inv_fwd(inv_bwd(s))))

s_init = bytes.fromhex('e72566c38389')
pb_base = bytearray(rom[:248])

target_prefix = 'csaw{'
target_mods = [ord(c) - 32 for c in target_prefix]

s_sched_cands = []
for i in range(5):
    t_mod = target_mods[i]
    f06_val = pb_base[0x8c + 5 * i] ^ s_init[i]
    cands_i = []
    for k in range(3):
        val = t_mod + k * 95
        if val < 256:
            s_val = (val - f06_val) & 0xff
            cands_i.append(s_val)
    s_sched_cands.append(cands_i)

def f06_sim(idx3d, idx3e):
    b = pb_base[0x8c + idx3d] ^ s_init[idx3e]
    idx3d += 5
    if idx3d >= 42:
        idx3d -= 42
    idx3e += 1
    if idx3e >= 6:
        idx3e -= 6
    return b, idx3d, idx3e

def render_check(s_sched):
    idx3d = 0
    idx3e = 0
    out = []
    
    for i in range(6):
        reg_a = s_sched[i]
        reg_b, idx3d, idx3e = f06_sim(idx3d, idx3e)
        reg_a = (reg_a + reg_b) & 0xff
        out.append((reg_a % 95) + 32)
        
    regs = list(s_sched)
    
    for count in range(36, 0, -1):
        reg_a = regs[5]
        reg_b = regs[0]
        reg_a = (reg_a + reg_b) & 0xff
        reg_b = regs[2]
        reg_a = (reg_a ^ reg_b) & 0xff
        reg_b = regs[4]
        reg_a = (reg_a + reg_b) & 0xff
        reg_a = (reg_a * 0x67) & 0xff
        reg_b = reg_a >> 3
        reg_a = (reg_a ^ reg_b) & 0xff
        reg_b = regs[1]
        reg_a = (reg_a ^ reg_b) & 0xff
        reg_b = regs[3]
        reg_a = (reg_a + reg_b) & 0xff
        reg_b = count
        reg_a = (reg_a ^ reg_b) & 0xff
        reg_a = (reg_a + 0x9e) & 0xff
        
        regs[0:5] = regs[1:6]
        regs[5] = reg_a
        
        reg_b, idx3d, idx3e = f06_sim(idx3d, idx3e)
        reg_a = (reg_a + reg_b) & 0xff
        out.append((reg_a % 95) + 32)
        
    return bytes(out)

for c0, c1, c2, c3, c4 in itertools.product(*s_sched_cands):
    for c5 in range(256):
        sched_tuple = [c0, c1, c2, c3, c4, c5]
        stem = render_check(sched_tuple)
        if stem[-1] == ord('}'):
            s_mixed = inv_key_sched(sched_tuple)
            key = bytes(s_mixed[i] ^ s_init[i] for i in range(6))
            try:
                flag = stem.decode()
            except Exception:
                continue
            if flag.startswith('csaw{') and flag.endswith('}'):
                if any(kw in flag for kw in ['love', 'computer', 'music', 'ninajirachi', 'csirac']):
                    print(f'[+] Recovered Key: {key.hex()}')
                    print(f'[+] Recovered Flag: {flag}')
                    sys.exit(0)

import os
import pefile
import unicorn
from unicorn.x86_const import *

def extract_equations(exe_path):
    pe = pefile.PE(exe_path)
    image_base = pe.OPTIONAL_HEADER.ImageBase

    mu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)

    for s in pe.sections:
        va = image_base + s.VirtualAddress
        size = (s.Misc_VirtualSize + 0xfff) & ~0xfff
        data = s.get_data()
        mu.mem_map(va, size)
        mu.mem_write(va, data + bytes(size - len(data)))

    STACK_BASE = 0x70000000
    STACK_SIZE = 0x100000
    mu.mem_map(STACK_BASE, STACK_SIZE)
    RBP = STACK_BASE + 0x80000
    RSP = RBP - 0x80
    mu.reg_write(UC_X86_REG_RSP, RSP)
    mu.reg_write(UC_X86_REG_RBP, RBP)

    OUT_BUF = 0x80000000
    mu.mem_map(OUT_BUF, 0x1000)

    def hook_code(uc, address, size, user_data):
        if address == 0x140026550:  # memset
            rcx = uc.reg_read(UC_X86_REG_RCX)
            edx = uc.reg_read(UC_X86_REG_RDX) & 0xff
            r8 = uc.reg_read(UC_X86_REG_R8)
            uc.mem_write(rcx, bytes([edx] * r8))
            rsp = uc.reg_read(UC_X86_REG_RSP)
            ret_addr = int.from_bytes(uc.mem_read(rsp, 8), 'little')
            uc.reg_write(UC_X86_REG_RSP, rsp + 8)
            uc.reg_write(UC_X86_REG_RIP, ret_addr)

    mu.hook_add(unicorn.UC_HOOK_CODE, hook_code)

    mu.reg_write(UC_X86_REG_RCX, OUT_BUF)
    mu.mem_write(RSP - 8, (0x13370000).to_bytes(8, 'little'))
    mu.reg_write(UC_X86_REG_RSP, RSP - 8)
    mu.emu_start(0x140001b70, 0x13370000)

    records_raw = mu.mem_read(OUT_BUF, 288)
    eqs = []
    for i in range(48):
        rec = records_raw[i*6:(i+1)*6]
        b0, b1, b2, b3 = rec[0], rec[1], rec[2], rec[3]
        target = int.from_bytes(rec[4:6], 'little')
        eqs.append((b0, b1, b2, b3, target))
    return eqs

def eval_eq(b0, b1, b2, b3, v0, v1, v2, v3):
    C1 = 0x9e3779b97f4a7c15
    C2 = 0x3c6ef372fe94f82a
    C3 = 0xdaa66d2c7ddf743f
    C4 = 0x78dde6e5fd29f054
    C5 = 0x1715609f7c746c69
    C6 = 0xb54cda58fbbee87e
    M1 = 0xbf58476d1ce4e5b9
    M2 = 0x94d049bb133111eb
    MASK64 = 0xffffffffffffffff
    
    seed = (b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)) ^ 0x6a09e667f3bcc909
    
    def f_mix(val):
        t = (seed + val) & MASK64
        t2 = (t ^ (t >> 0x1e)) * M1 & MASK64
        return t2 >> 0x1b, t2
        
    r9_hi, rax = f_mix(C1)
    r10_hi, rdx = f_mix(C2)
    r11_hi, r14 = f_mix(C3)
    r12_hi, r8 = f_mix(C4)
    r13_hi, rsi_val = f_mix(C5)
    rcx_hi, r15_val = f_mix(C6)
    
    r9 = (r9_hi ^ rax) * M2 & MASK64
    r10 = (r10_hi ^ rdx) * M2 & MASK64
    r11 = (r11_hi ^ r14) * M2 & MASK64
    r12 = (r12_hi ^ r8) * M2 & MASK64
    r13 = (r13_hi ^ rsi_val) * M2 & MASK64
    rcx_val = (rcx_hi ^ r15_val) * M2 & MASK64
    
    rbx_c = (rcx_val ^ (rcx_val >> 0x1f)) % 257
    rax_c = (r13 ^ (r13 >> 0x1f)) & 0xffffffff
    rcx_c = (r12 ^ (r12 >> 0x1f)) & 0xffffffff
    rdx_c = (r11 ^ (r11 >> 0x1f)) & 0xffffffff
    rsi_c = (r10 ^ (r10 >> 0x1f)) & 0xffffffff
    rdi_c = (r9 ^ (r9 >> 0x1f)) & 0xffffffff
    
    k0 = (rdi_c & 0xff) + 1
    k1 = (rsi_c & 0xff) + 1
    k2 = (rcx_c & 0xff) + 1
    k3 = (rax_c & 0xff) + 1
    k4 = (rdx_c & 0xff) + 1
    
    rdi = k0 * v0 + rbx_c
    rbx = k1 * v1 + rdi
    r15 = (v3 ^ v1) * k2
    rcx_res = (k3 * v1 + k4 * v2) * v2 + rbx + r15
    return rcx_res % 257

def solve():
    curr_dir = os.path.dirname(os.path.abspath(__file__))
    exe_path = os.path.join(curr_dir, '..', 'neon-causality.exe')
    if not os.path.exists(exe_path):
        exe_path = os.path.join(curr_dir, 'neon-causality.exe')
    eqs = extract_equations(exe_path)
    
    flag = [None] * 48
    progress = True
    while progress:
        progress = False
        for b0, b1, b2, b3, target in eqs:
            unknowns = []
            for idx in [b0, b1, b2, b3]:
                if idx != 255 and flag[idx] is None and idx not in unknowns:
                    unknowns.append(idx)
            if len(unknowns) == 1:
                u = unknowns[0]
                cand = []
                for c in range(0x20, 0x7f):
                    v0 = c if b0 == u else (flag[b0] if b0 != 255 else 0)
                    v1 = c if b1 == u else (flag[b1] if b1 != 255 else 0)
                    v2 = c if b2 == u else (flag[b2] if b2 != 255 else 0)
                    v3 = c if b3 == u else (flag[b3] if b3 != 255 else 0)
                    if eval_eq(b0, b1, b2, b3, v0, v1, v2, v3) == target:
                        cand.append(c)
                if len(cand) == 1:
                    flag[u] = cand[0]
                    progress = True
    
    flag_str = 'e0f{' + bytes(flag).decode() + '}'
    print(flag_str)
    return flag_str

if __name__ == '__main__':
    solve()

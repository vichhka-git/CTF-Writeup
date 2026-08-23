#!/usr/bin/env python3
import struct
import pefile
from unicorn import *
from unicorn.x86_const import *

def solve():
    pe = pefile.PE("../parallax-engine.exe")
    image_base = pe.OPTIONAL_HEADER.ImageBase

    def get_data(va, size):
        rva = va - image_base
        for s in pe.sections:
            if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
                off = rva - s.VirtualAddress
                return s.get_data()[off:off+size]
        return b""

    # 1. Emulate main.q2 in Unicorn to generate the 192 VM instructions
    text_section = None
    for s in pe.sections:
        if b".text" in s.Name:
            text_section = s
            break

    code = text_section.get_data()
    code_addr = image_base + text_section.VirtualAddress

    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    mu.mem_map(code_addr & ~0xfff, (len(code) + 0x1000) & ~0xfff)
    mu.mem_write(code_addr, code)

    stack_base = 0x70000000
    stack_size = 0x1000000
    mu.mem_map(stack_base, stack_size)
    initial_rsp = stack_base + stack_size - 0x10000
    mu.reg_write(UC_X86_REG_RSP, initial_rsp)
    mu.reg_write(UC_X86_REG_RBP, initial_rsp)

    g_addr = 0x60000000
    mu.mem_map(g_addr, 0x10000)
    mu.mem_write(g_addr + 0x10, struct.pack("<Q", stack_base + 0x1000))
    mu.reg_write(UC_X86_REG_R14, g_addr)

    q2_start = 0x1400a6da0
    q2_ret = 0x1400a7069
    mu.emu_start(q2_start, q2_ret, timeout=5000000)

    table_data = mu.mem_read(initial_rsp + 8, 0x3c0 * 8)

    # 2. PRNG function q5
    def prng_q5(rax, rbx):
        rcx = (rax + 1) & 0xffffffffffffffff
        rdx = (0xbb67ae8584caa73b * rcx) & 0xffffffffffffffff
        rcx = (0xa54ff53a5f1d36f1 ^ rdx) & 0xffffffffffffffff
        val = rcx
        for _ in range(rbx + 1):
            val = (val + 0x9e3779b97f4a7c15) & 0xffffffffffffffff
        
        rdx = 0x9e3779b97f4a7c15
        rax_res = (rdx + val) & 0xffffffffffffffff
        
        rcx = (rax_res ^ (rax_res >> 30)) & 0xffffffffffffffff
        rcx = (rcx * 0xbf58476d1ce4e5b9) & 0xffffffffffffffff
        rcx = (rcx ^ (rcx >> 27)) & 0xffffffffffffffff
        rcx = (rcx * 0x94d049bb133111eb) & 0xffffffffffffffff
        rcx = (rcx ^ (rcx >> 31)) & 0xffffffffffffffff
        return rcx

    def rol(val, n):
        n = n % 64
        return ((val << n) | (val >> (64 - n))) & 0xffffffffffffffff

    def ror(val, n):
        n = n % 64
        return ((val >> n) | (val << (64 - n))) & 0xffffffffffffffff

    def mod_inv64(a):
        return pow(a, -1, 1 << 64)

    # 3. Invert VM
    def run_vm_reverse(final_state):
        state = [0]*8
        for rax in range(8):
            rot = (9 * rax + 5) & 63
            rdx = ror(final_state[rax], rot)
            src_idx = (3 * rax + 5) & 7
            state[src_idx] = rdx ^ 0x6a09e667f3bcc909
            
        for i in range(191, -1, -1):
            instr = table_data[i*40 : (i+1)*40]
            op = instr[0]
            rsi = instr[1]
            rdi = instr[2]
            arg0, arg1, arg2, arg3 = struct.unpack("<4Q", instr[8:40])
            
            if op == 0:
                rbx = rol(state[rdi], arg0)
                rbx = (rbx + arg2) & 0xffffffffffffffff
                state[rsi] = (state[rsi] - rbx) & 0xffffffffffffffff
            elif op == 1:
                rbx = rol(state[rdi], arg0)
                rbx ^= arg2
                state[rsi] ^= rbx
            elif op == 2:
                state[rsi] = ror(state[rsi], arg0)
            elif op == 3:
                inv = mod_inv64(arg2)
                state[rsi] = (state[rsi] * inv) & 0xffffffffffffffff
            elif op == 4:
                state[rsi], state[rdi] = state[rdi], state[rsi]
            elif op == 5:
                rbx_rot = rol(state[rsi], arg1)
                state[rdi] ^= (rbx_rot ^ arg3)
                rbx = rol(state[rdi], arg0)
                rbx = (rbx + arg2) & 0xffffffffffffffff
                state[rsi] = (state[rsi] - rbx) & 0xffffffffffffffff
            else:
                raise ValueError(f"Unknown op {op}")
                
        for rcx in range(8):
            rdx = (0xa54ff53a5f1d36f1 * rcx + 0x3c6ef372fe94f82b) & 0xffffffffffffffff
            shift = (7 * rcx + 3) & 63
            rdx = rol(rdx, shift)
            state[rcx] ^= rdx
            
        return state

    # Target index for 'e0f{' is 2: (101*3 + 48*5 + 102*7 + 123*11) & 3 = 2
    idx = 2
    target_addr = 0x1401880a0 + idx * 64
    raw_bytes = get_data(target_addr, 64)
    qwords = struct.unpack("<8Q", raw_bytes)
    target_state = []
    for rbx in range(8):
        k = prng_q5(idx, rbx)
        target_state.append(k ^ qwords[rbx])

    rev_state = run_vm_reverse(target_state)

    permuted_bytes = bytearray(struct.pack("<6Q", *rev_state[:6]))

    prng_state = 0x1e285bbfdbd791ca
    recovered_chars = [0]*48
    for rcx in range(48):
        prng_state = (prng_state + 0x9e3779b97f4a7c15) & 0xffffffffffffffff
        z = prng_state
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9 & 0xffffffffffffffff
        z = (z ^ (z >> 27)) * 0x94d049bb133111eb & 0xffffffffffffffff
        z = (z ^ (z >> 31)) & 0xffffffffffffffff
        key_byte = (z >> 56) & 0xff
        
        pos = (17 * rcx + 11) % 48
        recovered_chars[rcx] = permuted_bytes[pos] ^ key_byte

    flag_inner = bytes(recovered_chars).decode()
    flag = f"e0f{{{flag_inner}}}"
    print(f"FLAG: {flag}")
    return flag

if __name__ == "__main__":
    solve()

#!/usr/bin/env python3
import struct
import os
from unicorn import *
from unicorn.x86_const import *

def main():
    binary_path = os.path.join(os.path.dirname(__file__), "..", "nan-penguin-cipher")
    if not os.path.exists(binary_path):
        binary_path = "nan-penguin-cipher"
    
    with open(binary_path, "rb") as f:
        elf = f.read()

    # 1. Compute target expected ciphertext qwords from binary
    def get_bytes(addr, length):
        off = addr - 0x400000
        return elf[off:off+length]

    data = get_bytes(0x483230, 48)
    data_qwords = struct.unpack("<6Q", data)

    M64 = 0xffffffffffffffff
    r11 = 0x9e3779b97f4a7c15
    r9 = 0xbf58476d1ce4e5b9
    r8 = 0x94d049bb133111eb
    rdx_init = 0x13198a2e03707344

    expected = []
    rax = 2
    rax = (rax * r11) & M64
    rax = (rax ^ rdx_init) & M64

    for i in range(6):
        mult = (i + 1) * r11 & M64
        rcx = (mult + rax) & M64
        rdx = (rcx ^ (rcx >> 30)) & M64
        rdx = (rdx * r9) & M64
        rcx = (rdx ^ (rdx >> 27)) & M64
        rcx = (rcx * r8) & M64
        
        rsi = data_qwords[i]
        val = ((rcx >> 31) ^ (rsi ^ rcx)) & M64
        expected.append(val)

    expected_bytes = struct.pack("<6Q", *expected)

    # 2. Emulate key setup in Unicorn up to 0x403da1
    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    mu.mem_map(0x400000, 2 * 1024 * 1024)
    mu.mem_write(0x400000, elf[:2*1024*1024])
    stack = 0x7fff0000
    mu.mem_map(stack, 1024 * 1024)
    mu.reg_write(UC_X86_REG_RSP, stack + 1024 * 1024 // 2)
    fs_base = 0x600000
    mu.mem_map(fs_base, 0x1000)
    mu.reg_write(UC_X86_REG_FS_BASE, fs_base)
    mu.mem_write(fs_base + 0x28, b"\x00"*8)

    payload_addr = stack + 0x1000
    mu.mem_write(payload_addr, b"A"*48)
    mu.reg_write(UC_X86_REG_RDI, payload_addr)

    mu.emu_start(0x403800, 0x403da1)

    rsp = mu.reg_read(UC_X86_REG_RSP)
    stack_data = mu.mem_read(rsp, 0xe48)

    r14_offset = 0x20

    def gf_mul(a, b):
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi = a & 0x80
            a = (a << 1) & 0xff
            if hi:
                a ^= 0x1b
            b >>= 1
        return p

    gf_inv_table = {}
    for kb in range(1, 256):
        inv = {}
        for db in range(256):
            res = gf_mul(db, kb)
            inv[res] = db
        gf_inv_table[kb] = inv

    def rol64(val, count):
        count %= 64
        return ((val << count) | (val >> (64 - count))) & 0xffffffffffffffff

    def ror64(val, count):
        count %= 64
        return ((val >> count) | (val << (64 - count))) & 0xffffffffffffffff

    rounds_keys = []
    for r in range(18):
        block = stack_data[r14_offset + r * 200 : r14_offset + (r + 1) * 200]
        key1 = struct.unpack("<6Q", block[0:48])
        key2 = struct.unpack("<6Q", block[48:96])
        key3 = struct.unpack("<6Q", block[96:144])
        key4 = struct.unpack("<6Q", block[144:192])
        shift1 = list(block[192:198])
        shift_words = block[198]
        rounds_keys.append({
            "key1": key1,
            "key2": key2,
            "key3": key3,
            "key4": key4,
            "shift1": shift1,
            "shift_words": shift_words % 6
        })

    def py_decrypt(ct_bytes):
        W = list(struct.unpack("<6Q", ct_bytes))
        r10_const = 0x37b9d5fa7c3e16d
        
        for r in range(17, -1, -1):
            rk = rounds_keys[r]
            
            # Part 3 Inverse: Word unpermutation
            sw = rk["shift_words"]
            old_W = [0] * 6
            for i in range(6):
                old_W[i] = W[(sw + i) % 6]
            W = old_W
            
            # Part 2 Inverse: Feistel unmixing
            for r11 in range(6, 0, -1):
                target_idx = r11 % 6
                source_idx = r11 - 1
                src_val = W[source_idx]
                
                k1_idx = (r11 + 2) % 6
                k1_val = rk["key1"][k1_idx]
                
                rbx = (k1_val + src_val) & M64
                shift_idx = (r11 + 1) % 6
                shift_val = rk["shift1"][shift_idx]
                rbx = rol64(rbx, shift_val)
                
                r8 = (rol64(k1_val, 0x11) ^ src_val) & M64
                
                rdi = 0
                for b in range(8):
                    db = (r8 >> (8 * b)) & 0xff
                    kb = (r10_const >> (8 * b)) & 0xff
                    if kb == 0:
                        kb = 0x63
                    out_b = gf_mul(db, kb)
                    rdi |= (out_b << (8 * b))
                
                W[target_idx] = (W[target_idx] ^ rbx ^ rdi) & M64
                
            # Part 1 Inverse: Word unsubstitution
            for i in range(6):
                w = W[i]
                w = ror64(w, rk["shift1"][i])
                
                k4 = rk["key4"][i]
                res_w = 0
                for b in range(8):
                    out_b = (w >> (8 * b)) & 0xff
                    kb = (k4 >> (8 * b)) & 0xff
                    if kb == 0:
                        kb = 0x63
                    db = gf_inv_table[kb][out_b]
                    res_w |= (db << (8 * b))
                
                inv_k3 = pow(rk["key3"][i], -1, 1 << 64)
                w = (res_w * inv_k3) & M64
                w = (w - rk["key2"][i]) & M64
                w = (w ^ rk["key1"][i]) & M64
                W[i] = w
                
        return struct.pack("<6Q", *W)

    decrypted_intermediate = py_decrypt(expected_bytes)

    # 3. Invert PRNG permutation and XOR keystream
    r11 = 0x9e3779b97f4a7c15
    r9 = 0xbf58476d1ce4e5b9
    r8 = 0x94d049bb133111eb
    rdx = 0x6e616e5f676f626c
    rbx = 0x18c841274566a65c
    ecx = 7
    M32 = 0xffffffff

    recovered_flag_chars = [0] * 48

    for k in range(48):
        rdx = (rdx + r11) & M64
        edi = ecx % 48
        ecx = (ecx + 29) & M32
        
        rax = rdx ^ (rdx >> 30)
        rax = (rax * r9) & M64
        r12 = rax ^ (rax >> 27)
        r12 = (r12 * r8) & M64
        kb = ((r12 ^ (r12 >> 31)) & M64) >> 56
        
        val_at_edi = decrypted_intermediate[edi]
        input_k = val_at_edi ^ kb
        recovered_flag_chars[k] = input_k

    flag_body = bytes(recovered_flag_chars).decode("latin1")
    flag = f"e0f{{{flag_body}}}"
    print(flag)

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Reproducible solver for CSAW CTF 2026 - Rev: Autobahn (ID: 35)

Challenge binary: nitro (ELF 64-bit not stripped)
Vulnerability / Mechanism:
1. main() uses mprotect(PROT_READ|PROT_WRITE|PROT_EXEC) on the page containing secret_check (0x40130d).
2. It decrypts 350 bytes of secret_check using an 8-byte repeating XOR key smc_key.0:
   smc_key.0 = b"\x137\xc0\xde\xba\xad\xf0\r" (0x1337c0debaadf00d)
3. The decrypted secret_check verifies that argv[1] == "n2o_boost" (9 bytes).
4. If correct, it decodes enc_flag (47 bytes at 0x402020) using:
   for i in range(47):
       b_code = decrypted_code[(7 * i + 3) % 350]
       flag[i] = enc_flag[i] ^ ((0x6b + b_code + 5 * i) & 0xff)
   and prints "NITRO ENGAGED: <flag>".
"""

import os
import struct
import subprocess
from pathlib import Path

CHALLENGE_DIR = Path(__file__).resolve().parent.parent
BINARY_PATH = CHALLENGE_DIR / "files" / "nitro"

def solve():
    if not BINARY_PATH.exists():
        raise FileNotFoundError(f"Binary not found at {BINARY_PATH}")

    # Method 1: Pure static extraction and calculation from binary bytes
    with open(BINARY_PATH, "rb") as f:
        data = f.read()

    # Parse ELF segments to map virtual addresses to file offsets
    e_phoff = struct.unpack("<Q", data[32:40])[0]
    e_phnum = struct.unpack("<H", data[56:58])[0]
    segments = []
    for i in range(e_phnum):
        ph = data[e_phoff + i*56 : e_phoff + (i+1)*56]
        p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack("<IIQQQQQQ", ph)
        if p_type == 1:
            segments.append((p_vaddr, p_offset, p_filesz))

    def vaddr_to_offset(vaddr):
        for va, off, fsz in segments:
            if va <= vaddr < va + fsz:
                return off + (vaddr - va)
        raise ValueError(f"vaddr {hex(vaddr)} not found")

    # Extract smc_key (0x4020a8)
    smc_key = data[vaddr_to_offset(0x4020a8) : vaddr_to_offset(0x4020a8) + 8]

    # Decrypt secret_check (0x40130d .. 0x40146b, 350 bytes)
    code_off = vaddr_to_offset(0x40130d)
    enc_code = bytearray(data[code_off : code_off + 350])
    for i in range(len(enc_code)):
        enc_code[i] ^= smc_key[i % 8]
    dec_code = bytes(enc_code)

    # Extract enc_flag (0x402020, 47 bytes)
    enc_flag_off = vaddr_to_offset(0x402020)
    enc_flag = data[enc_flag_off : enc_flag_off + 47]

    # Reconstruct flag
    flag = bytearray(47)
    for i in range(47):
        rem = (7 * i + 3) % 350
        b_code = dec_code[rem]
        eax = (0x6b + b_code + 5 * i) & 0xff
        flag[i] = enc_flag[i] ^ eax

    flag_str = flag.decode("utf-8")
    print(f"Password: n2o_boost")
    print(f"Flag: {flag_str}")

    # Method 2: Verify by directly running the binary if on Linux
    if os.access(BINARY_PATH, os.X_OK) or os.name == "posix":
        os.chmod(BINARY_PATH, 0o755)
        res = subprocess.run([str(BINARY_PATH), "n2o_boost"], capture_output=True, text=True)
        if flag_str in res.stdout:
            print(f"Binary verification: SUCCESS ({res.stdout.strip()})")

    return flag_str

if __name__ == "__main__":
    solve()

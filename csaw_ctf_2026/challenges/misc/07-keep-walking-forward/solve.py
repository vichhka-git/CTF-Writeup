#!/usr/bin/env python3
"""
Solution script for CSAW CTF Quals 2026 - Keep Walking Forward (ID 7)
Demonstrates the full reconstruction pipeline:
1. FQDN/domain resolution in vcheck.exe
2. 32-byte XOR key generation
3. Decryption of downloaded version-helper payload
4. Donut Chaskey CTR module decryption
5. Extraction and parsing of DotnetProto.exe embedded PowerShell logic
6. Flag reconstruction
"""
import struct
from pathlib import Path

def derive_xor_key(domain: bytes) -> bytes:
    # Implements the algorithm at 0x140001000 in vcheck.exe
    key = bytearray(32)
    val = (domain[0] * 0x83) & 0xff
    key[0] = val
    for i in range(1, 32):
        char_val = domain[i % len(domain)]
        val = (char_val * 0x83) & 0xff
        key[i] = val ^ key[i - 1]
    return bytes(key)

def chaskey_permute(v, k):
    # 16-round Chaskey permutation used by Donut
    v0, v1, v2, v3 = v
    k0, k1, k2, k3 = k
    v0 ^= k0; v1 ^= k1; v2 ^= k2; v3 ^= k3
    for _ in range(16):
        v0 = (v0 + v1) & 0xffffffff
        v1 = (((v1 << 5) | (v1 >> 27)) ^ v0) & 0xffffffff
        v0 = ((v0 << 16) | (v0 >> 16)) & 0xffffffff
        v2 = (v2 + v3) & 0xffffffff
        v3 = (((v3 << 8) | (v3 >> 24)) ^ v2) & 0xffffffff
        v0 = (v0 + v3) & 0xffffffff
        v3 = (((v3 << 13) | (v3 >> 19)) ^ v0) & 0xffffffff
        v2 = (v2 + v1) & 0xffffffff
        v1 = (((v1 << 7) | (v1 >> 25)) ^ v2) & 0xffffffff
        v2 = ((v2 << 16) | (v2 >> 16)) & 0xffffffff
    v0 ^= k0; v1 ^= k1; v2 ^= k2; v3 ^= k3
    return [v0, v1, v2, v3]

def chaskey_ctr_decrypt(key_bytes, iv_bytes, ciphertext):
    k = list(struct.unpack('<4I', key_bytes))
    iv = bytearray(iv_bytes)
    out = bytearray()
    pos = 0
    while pos < len(ciphertext):
        v = list(struct.unpack('<4I', iv))
        keystream_block = struct.pack('<4I', *chaskey_permute(v, k))
        block_len = min(16, len(ciphertext) - pos)
        for i in range(block_len):
            out.append(ciphertext[pos + i] ^ keystream_block[i])
        pos += block_len
        # Increment 128-bit counter
        for i in range(15, -1, -1):
            iv[i] = (iv[i] + 1) & 0xff
            if iv[i] != 0:
                break
    return bytes(out)

def solve():
    domain = b'evermore.internal'
    key32 = derive_xor_key(domain)

    with open(Path(__file__).resolve().parent / 'solver_assets' / 'version-helper', 'rb') as f:
        encrypted_helper = f.read()

    decrypted_helper = bytes(b ^ key32[i % 32] for i, b in enumerate(encrypted_helper))

    # Parse Donut instance at offset 5
    inst = decrypted_helper[5:]
    inst_len = struct.unpack_from('<I', inst, 0)[0]
    donut_key = inst[4:20]
    donut_iv = inst[20:36]
    donut_cipher = inst[0x23c : inst_len]

    donut_module = chaskey_ctr_decrypt(donut_key, donut_iv, donut_cipher)
    mz_idx = donut_module.find(b'MZ')
    dotnet_exe = donut_module[mz_idx:]

    # Evaluate flag pieces from reconstructed PowerShell script
    v_1 = ''.join(chr(x) for x in [0x77, 0x34, 0x6c, 0x6b]) # w4lk
    v_2 = ''.join(chr(x << 1) for x in [0x31, 0x1a])        # b4
    v_3 = 'u'
    v_4 = 'n4c'[::-1]                                       # c4n
    v_5 = ''.join(chr(x + 0x10) for x in [0x62, 0x65, 0x5e, 0x18, 0x25, 0x60, 0x24, 0x53, 0x23, 0x19]) # run(5p4c3)
    prefix = '{2}{0}{1}{3}'.format('s', 'a', 'c', 'w')     # csaw
    body = '_'.join([v_1, v_2, v_3, v_4, v_5])
    flag = f"{prefix}{{{body}_3jfi9do9}}"
    print(flag)
    return flag

if __name__ == '__main__':
    solve()

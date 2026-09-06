#!/usr/bin/env python3
"""
Solver script for Qfact (Forensics) - BlackHat MEA Qualification CTF 2026
Recovers the malicious HTA payload from Windows Defender Quarantine,
extracts the ransomware encryption logic and credentials,
decrypts affected files, and extracts the flag.
"""

import base64
import glob
import hashlib
import os
import pathlib
import struct
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

CHALLENGE_DIR = pathlib.Path(__file__).resolve().parent

def mse_ksa():
    """Microsoft Security Essentials / Windows Defender RC4 S-box key schedule."""
    key = [
        0x1E, 0x87, 0x78, 0x1B, 0x8D, 0xBA, 0xA8, 0x44, 0xCE, 0x69,
        0x70, 0x2C, 0x0C, 0x78, 0xB7, 0x86, 0xA3, 0xF6, 0x23, 0xB7,
        0x38, 0xF5, 0xED, 0xF9, 0xAF, 0x83, 0x53, 0x0F, 0xB3, 0xFC,
        0x54, 0xFA, 0xA2, 0x1E, 0xB9, 0xCF, 0x13, 0x31, 0xFD, 0x0F,
        0x0D, 0xA9, 0x54, 0xF6, 0x87, 0xCB, 0x9E, 0x18, 0x27, 0x96,
        0x97, 0x90, 0x0E, 0x53, 0xFB, 0x31, 0x7C, 0x9C, 0xBC, 0xE4,
        0x8E, 0x23, 0xD0, 0x53, 0x71, 0xEC, 0xC1, 0x59, 0x51, 0xB8,
        0xF3, 0x64, 0x9D, 0x7C, 0xA3, 0x3E, 0xD6, 0x8D, 0xC9, 0x04,
        0x7E, 0x82, 0xC9, 0xBA, 0xAD, 0x97, 0x99, 0xD0, 0xD4, 0x58,
        0xCB, 0x84, 0x7C, 0xA9, 0xFF, 0xBE, 0x3C, 0x8A, 0x77, 0x52,
        0x33, 0x55, 0x7D, 0xDE, 0x13, 0xA8, 0xB1, 0x40, 0x87, 0xCC,
        0x1B, 0xC8, 0xF1, 0x0F, 0x6E, 0xCD, 0xD0, 0x83, 0xA9, 0x59,
        0xCF, 0xF8, 0x4A, 0x9D, 0x1D, 0x50, 0x75, 0x5E, 0x3E, 0x19,
        0x18, 0x18, 0xAF, 0x23, 0xE2, 0x29, 0x35, 0x58, 0x76, 0x6D,
        0x2C, 0x07, 0xE2, 0x57, 0x12, 0xB2, 0xCA, 0x0B, 0x53, 0x5E,
        0xD8, 0xF6, 0xC5, 0x6C, 0xE7, 0x3D, 0x24, 0xBD, 0xD0, 0x29,
        0x17, 0x71, 0x86, 0x1A, 0x54, 0xB4, 0xC2, 0x85, 0xA9, 0xA3,
        0xDB, 0x7A, 0xCA, 0x6D, 0x22, 0x4A, 0xEA, 0xCD, 0x62, 0x1D,
        0xB9, 0xF2, 0xA2, 0x2E, 0xD1, 0xE9, 0xE1, 0x1D, 0x75, 0xBE,
        0xD7, 0xDC, 0x0E, 0xCB, 0x0A, 0x8E, 0x68, 0xA2, 0xFF, 0x12,
        0x63, 0x40, 0x8D, 0xC8, 0x08, 0xDF, 0xFD, 0x16, 0x4B, 0x11,
        0x67, 0x74, 0xCD, 0x0B, 0x9B, 0x8D, 0x05, 0x41, 0x1E, 0xD6,
        0x26, 0x2E, 0x42, 0x9B, 0xA4, 0x95, 0x67, 0x6B, 0x83, 0x98,
        0xDB, 0x2F, 0x35, 0xD3, 0xC1, 0xB9, 0xCE, 0xD5, 0x26, 0x36,
        0xF2, 0x76, 0x5E, 0x1A, 0x95, 0xCB, 0x7C, 0xA4, 0xC3, 0xDD,
        0xAB, 0xDD, 0xBF, 0xF3, 0x82, 0x53
    ]
    sbox = list(range(256))
    j = 0
    for i in range(256):
        j = (j + sbox[i] + key[i]) % 256
        sbox[i], sbox[j] = sbox[j], sbox[i]
    return sbox

def rc4_decrypt(data):
    """Decrypt Defender quarantine data using Defender's fixed RC4 S-box."""
    sbox = mse_ksa()
    out = bytearray(len(data))
    i = 0
    j = 0
    for k in range(len(data)):
        i = (i + 1) % 256
        j = (j + sbox[i]) % 256
        sbox[i], sbox[j] = sbox[j], sbox[i]
        val = sbox[(sbox[i] + sbox[j]) % 256]
        out[k] = val ^ data[k]
    return bytes(out)

def extract_quarantined_payload(raw_bytes):
    """Carve the quarantined payload from ResourceData bytes."""
    decrypted = rc4_decrypt(raw_bytes)
    sd_len = struct.unpack_from('<I', decrypted, 0x8)[0]
    header_len = 0x28 + sd_len
    malfile_len = struct.unpack_from('<Q', decrypted, sd_len + 0x1C)[0]
    return decrypted[header_len:header_len + malfile_len]

def solve_from_zip(zf):
    print("[*] Decrypting Windows Defender Quarantine...")
    quar_names = [n for n in zf.namelist() if "Quarantine" in n and "ResourceData" in n and not n.endswith(("\\", "/"))]
    if not quar_names:
        raise FileNotFoundError("Quarantined payload file not found in Evidence.zip")
    raw_bytes = zf.read(quar_names[0])
    malware_bytes = extract_quarantined_payload(raw_bytes)
    print(f"[+] Successfully extracted {len(malware_bytes)} bytes of quarantined payload.")

    # 1. Recover AES key from VBScript constants: Chr(70) & Chr(120) ...
    # 'Fx7mK9vL2nQ4wPz!' padded right with spaces to 32 bytes
    k_chars = [70, 120, 55, 109, 75, 57, 118, 76, 50, 110, 81, 52, 119, 80, 122, 33]
    k_str = "".join(chr(c) for c in k_chars)
    aes_key = k_str.ljust(32, ' ').encode('utf-8')

    # 2. Recover AES IV: MD5(COMPUTERNAME + USERNAME)
    # Target: DESKTOP-KLPAT9O, User: jmartin (from READ_ME.txt ID and Registry)
    computer_name = "DESKTOP-KLPAT9O"
    user_name = "jmartin"
    iv = hashlib.md5((computer_name + user_name).encode('utf-8')).digest()

    print(f"[+] Recovered AES-256 Key: {aes_key}")
    print(f"[+] Recovered AES-CBC IV: {iv.hex()}")

    # 3. Decrypt EncryptedFiles
    enc_names = [n for n in zf.namelist() if n.endswith('.enc')]
    print(f"[*] Found {len(enc_names)} encrypted files to decrypt from zip.")
    flag = None
    for en in enc_names:
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        try:
            pt = unpad(cipher.decrypt(zf.read(en)), 16).decode('utf-8', errors='replace')
            for line in pt.splitlines():
                line = line.strip()
                if line.startswith("QkhGbGFnWX"):
                    flag = base64.b64decode(line).decode('utf-8')
                    print(f"[+] Flag recovered from {en}: {flag}")
        except Exception:
            continue

    if not flag:
        raise ValueError("Flag not found in decrypted files")
    return flag

def solve():
    zip_path = CHALLENGE_DIR / 'Evidence.zip'
    split_part = CHALLENGE_DIR / 'Evidence.z01'

    # If split zip parts exist, combine them temporarily
    if split_part.exists():
        import tempfile, subprocess
        with tempfile.TemporaryDirectory() as tmp_dir:
            combined = pathlib.Path(tmp_dir) / "combined.zip"
            print(f"[*] Recombining split zip {zip_path.name}...")
            subprocess.run(["zip", "-s", "0", str(zip_path), "--out", str(combined)], check=True, stdout=subprocess.DEVNULL)
            import zipfile
            with zipfile.ZipFile(combined) as zf:
                return solve_from_zip(zf)
    elif zip_path.exists():
        import zipfile
        with zipfile.ZipFile(zip_path) as zf:
            return solve_from_zip(zf)
    else:
        raise FileNotFoundError(f"{zip_path} not found")

if __name__ == '__main__':
    flag = solve()
    print(f"\n[+] FINAL FLAG: {flag}")

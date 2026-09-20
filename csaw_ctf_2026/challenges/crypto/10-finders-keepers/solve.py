#!/usr/bin/env python3
"""
Finders Keepers! - CSAW CTF 2026 Qualifications Solver
Category: Crypto / Stego
ID: 10

Mechanism:
1. Video metadata inspection:
   - Exif `Subject` field contains Base64-encoded ciphertext:
     `ZXNucHtkMGNfQHl6QGdsX21uMGpfcG0zejNfZzBfbzAwc30=`
     Decodes to: `esnp{d0c_@yz@gl_mn0j_pm3z3_g0_o00s}`
2. Video frame analysis:
   - The video contains moving pastel blocks covering a spinning wheel in the bottom-left corner.
   - Polar unwrap or frame inspection around frame 138 (at 30 fps) reveals sector text:
     `Y2FudGZpbmRpdA==`
     Decodes to: `cantfindit`
3. Decryption:
   - Standard Vigenere cipher on alphabetic letters using key `cantfindit` (advancing key only on letters).
   - Preserves symbols, underscores, and numbers.
   - Result: `csaw{y0u_@lw@ys_kn0w_wh3r3_t0_l00k}`
"""

import base64

def decrypt_vigenere(ct: str, key: str) -> str:
    pt = []
    k_idx = 0
    key = key.lower()
    for char in ct:
        if "a" <= char <= "z":
            shift = ord(key[k_idx % len(key)]) - ord("a")
            p = chr((ord(char) - ord("a") - shift) % 26 + ord("a"))
            pt.append(p)
            k_idx += 1
        elif "A" <= char <= "Z":
            shift = ord(key[k_idx % len(key)]) - ord("a")
            p = chr((ord(char) - ord("A") - shift) % 26 + ord("A"))
            pt.append(p)
            k_idx += 1
        else:
            pt.append(char)
    return "".join(pt)

def main():
    # 1. Ciphertext from exif metadata Subject:
    raw_b64 = "ZXNucHtkMGNfQHl6QGdsX21uMGpfcG0zejNfZzBfbzAwc30="
    ciphertext = base64.b64decode(raw_b64).decode("utf-8")
    print(f"[*] Decoded ciphertext: {ciphertext}")

    # 2. Key from video wheel sector:
    key_b64 = "Y2FudGZpbmRpdA=="
    key = base64.b64decode(key_b64).decode("utf-8")
    print(f"[*] Decoded key from wheel: {key}")

    # 3. Decrypt:
    flag = decrypt_vigenere(ciphertext, key)
    print(f"[+] Recovered flag: {flag}")
    assert flag == "csaw{y0u_@lw@ys_kn0w_wh3r3_t0_l00k}"
    return flag

if __name__ == "__main__":
    main()

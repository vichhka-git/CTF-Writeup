#!/usr/bin/env python3
"""
Solution script for COMPFEST 18 CTF - Backrooms (Reverse Engineering)
"""
import zipfile
import pefile
import os
import sys

def solve(path=None):
    exe_path = path or os.environ.get('CHALLENGE_FILE', 'extracted/rev_backrooms.exe')
    if not os.path.exists(exe_path):
        zip_path = os.environ.get('CHALLENGE_ARCHIVE', '../rev_backrooms_x86-64-Windows.zip')
        with zipfile.ZipFile(zip_path, 'r') as z:
            z.extract('rev_backrooms.exe', 'extracted')

    pe = pefile.PE(exe_path, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase

    with open(exe_path, 'rb') as f:
        raw = f.read()

    # Address of encrypted block in .rdata: VA 0x142f3f978
    target_va = 0x142f3f978
    rva = target_va - base

    raw_offset = None
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
            raw_offset = s.PointerToRawData + (rva - s.VirtualAddress)
            break

    if raw_offset is None:
        raise ValueError("Could not find section containing target VA")

    encrypted = raw[raw_offset : raw_offset + 60]

    # Decryption logic from startup system at 0x140005276
    seed = 0xa3f1924d
    r9b = 0xdb
    sil = 0

    bits = []
    for i in range(len(encrypted)):
        esi = sil
        rem = esi % 7
        seed = (seed * 0x41c64e6d + 0x3039) & 0xffffffff
        edi = (seed >> 16) & 0xff
        b = (encrypted[i] + r9b) & 0xff
        shift_r = rem + 1
        shift_l = 8 - shift_r
        b = ((b >> shift_r) | (b << shift_l)) & 0xff
        b ^= edi
        for bit_idx in range(7, -1, -1):
            bits.append((b >> bit_idx) & 1)
        r9b = (r9b + 0xf3) & 0xff
        sil = (sil + 1) & 0xff

    # Render 4x120 grid
    grid = [''.join('#' if bits[r*120 + c] else '.' for c in range(120)) for r in range(4)]
    print("Decoded 3D Block Matrix:")
    for row in grid:
        print(row)

    # 3x4 font dictionary
    font_map = {
        (".##", "#..", "#..", ".##"): "C",
        ("###", "#.#", "#.#", "###"): "O",
        ("##.", "###", "#.#", "#.#"): "M",
        ("###", "#.#", "###", "#.."): "P",
        ("###", "#..", "##.", "#.."): "F",
        ("###", "##.", "#..", "###"): "E",
        (".##", "##.", "..#", "##."): "S",
        ("###", ".#.", ".#.", ".#."): "T",
        ("##.", ".#.", ".#.", "###"): "1",
        (".##", "###", "#.#", "###"): "8",
        ("..#", "##.", ".#.", "..#"): "{",
        ("#.#", "###", "#.#", "#.#"): "H",
        ("###", ".#.", ".#.", "###"): "I",
        ("##.", ".##", "#..", "###"): "2",
        (".#.", "#.#", "#.#", ".#."): "0",
        ("#.#", "#.#", ".#.", ".#."): "Y",
        ("###", "#.#", "###", "#.#"): "A",
        ("###", "#.#", "##.", "#.#"): "R",
        ("#..", "#..", "#..", "###"): "L",
        ("##.", "#.#", "#.#", "##."): "D",
        ("#..", ".##", ".#.", "#.."): "}",
        ("...", "...", "...", "###"): "_",
    }

    flag_chars = []
    for c in range(0, 120, 4):
        glyph = tuple(grid[r][c:c+3] for r in range(4))
        ch = font_map.get(glyph, '?')
        flag_chars.append(ch)

    flag = "".join(flag_chars)
    print("\nFlag:", flag)
    return flag

if __name__ == '__main__':
    solve(sys.argv[1] if len(sys.argv) > 1 else None)

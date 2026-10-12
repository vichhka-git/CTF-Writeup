#!/usr/bin/env python3
import os
import sys

def solve():
    rom_path = os.path.join(os.path.dirname(__file__), "files", "meteor_shower.nes")
    if not os.path.exists(rom_path) and len(sys.argv) > 1:
        rom_path = sys.argv[1]

    with open(rom_path, "rb") as f:
        rom = f.read()

    # iNES header is 16 bytes, PRG ROM starts at 0x10 (mapped to $8000)
    prg = rom[16:16+32768]

    # Reconstruct expected bits from the 6502 check function at $8158:
    # Addresses $8718 and $8798 correspond to PRG offsets 0x718 and 0x798
    bits = []
    j = 0x0b
    for i in range(0x5f):  # 95 bits
        b1 = prg[0x718 + j]
        b2 = prg[0x798 + j]
        exp_bit = (b1 ^ b2 ^ i) & 1
        bits.append(exp_bit)
        j = (j + 0x25) & 0x7f

    # Decode using Bacon's cipher (5 bits per letter, 26-letter alphabet A=0..Z=25)
    # The hint in ROM easter egg text is:
    # "I HOPE YOU LIKE BACON & EGGS... FIVE STRIPS AT A TIME."
    letters = []
    for k in range(0, len(bits), 5):
        chunk = bits[k:k+5]
        val = 0
        for bit in chunk:
            val = (val << 1) | bit
        letters.append(chr(ord('A') + val))

    decoded = "".join(letters)  # "SCIENTIAPOTENTIAEST"

    # Split into words: "SCIENTIA", "POTENTIA", "EST"
    words = ["SCIENTIA", "POTENTIA", "EST"]
    flag = f"FortID{{{'_'.join(words)}}}"
    print(flag)
    return flag

if __name__ == "__main__":
    solve()

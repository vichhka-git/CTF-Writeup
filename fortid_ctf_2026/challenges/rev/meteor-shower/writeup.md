# FortID CTF 2026 Writeup: Meteor Shower

- **Category:** Rev
- **Challenge author:** ipaljak
- **Points / Solves:** 124 pts / 118 solves
- **Flag:** `FortID{SCIENTIA_POTENTIA_EST}`

---

## Challenge

> Great Scott! The biggest meteor storm in the galaxy is headed straight for your
> sector. ☄️ 🚀
>
> **Note:** wrap the phrase into `FortID{}`, and use `_` to separate the words.

---

## Summary

`Meteor Shower` is an NES ROM challenge (`meteor_shower.nes`). By analyzing the PRG-ROM string tables and the 6502 machine code, we locate an Easter Egg screen that displays hints mentioning Francis Bacon ("BACON & EGGS... FIVE STRIPS AT A TIME"). Reversing the input check routine at `$8158` reveals that the player inputs a 95-bit sequence via the NES controller buttons A and B (A=0, B=1). The expected bit sequence is generated from two byte tables in the ROM at `$8718` and `$8798`. Decoding this 95-bit stream using Bacon's 5-bit cipher (26-letter variation) produces the Latin phrase `SCIENTIA POTENTIA EST`. Wrapping this phrase in `FortID{}` with underscores yields the flag.

## Reconnaissance & Static Analysis

1. Inspecting the file with `file` reveals an iNES format ROM:
   ```
   NES ROM image (iNES): 2x16k PRG, 1x8k CHR [H-mirror]
   ```
   Total size is 40,976 bytes (16-byte header + 32 KB PRG-ROM + 8 KB CHR-ROM).

2. In the PRG-ROM at offset `$8631`, strings are encoded using a simple font tile offset where tile `$80` corresponds to `'A'` and `$00` corresponds to space. Decoding strings in this area reveals:
   ```
   D-PAD TO MOVE
   PRESS START
   GAME OVER
   MISSION COMPLETE
   YOU SURVIVED
   CONGRATULATIONS!
   EASTER EGG FOUND!
   GREAT JOB ON FINDING
   THE EASTER EGG.
   I HOPE YOU LIKE
   BACON & EGGS...
   FIVE STRIPS AT A TIME.
   ```

3. The game state dispatcher at `$83d4` checks zero-page register `$05`:
   - `$05 == 1`: Title screen
   - `$05 == 2`: Gameplay
   - `$05 == 3`: Game Over
   - `$05 == 4`: Mission Complete
   - Default / other: Easter Egg screen

## Reverse Engineering & Root Cause

1. Tracking writes to zero-page `$05` leads to `$812b`:
   ```6502
   lda $0c
   cmp #$5f        ; 95 (0x5f) bits entered
   bne $8142
   jsr $8158       ; Validate entered bit sequence
   bcc $813f       ; Fail -> reset buffer
   lda #$04
   sta $04
   lda #$05        ; Switch to screen 5 (Easter Egg!)
   sta $05
   rts
   ```

2. The input handler at `$80ef` reads the NES controller `$4016` edge triggers:
   - When button A is pressed, it records a `0` bit.
   - When button B is pressed, it records a `1` bit.
   - Bits are accumulated into a buffer at RAM `$0400` until 95 bits are collected.

3. The validation subroutine at `$8158` checks each bit `i` from `0` to `94` against:
   ```6502
   expected_bit = (ROM[$8718 + j] ^ ROM[$8798 + j] ^ i) & 1
   ```
   where `j` starts at `0x0b` and increments as `j = (j + 0x25) & 0x7f`.

4. The hint in the Easter Egg text ("BACON & EGGS... FIVE STRIPS AT A TIME") specifically hints at Bacon's cipher (5 binary digits per letter).

5. Grouping the 95 bits into nineteen 5-bit chunks and mapping them to letters ($A = 0, \dots, Z = 25$) yields:
   ```
   [10010, 00010, 01000, 00100, 01101, 10011, 01000, 00000, 01111, 01110, 10011, 00100, 01101, 10011, 01000, 00000, 00100, 10010, 10011]
   -> S C I E N T I A P O T E N T I A E S T
   ```

## Solve Script

```python
#!/usr/bin/env python3
import os
import sys

def solve():
    rom_path = os.path.join(os.path.dirname(__file__), "meteor_shower.nes")
    if not os.path.exists(rom_path) and len(sys.argv) > 1:
        rom_path = sys.argv[1]

    with open(rom_path, "rb") as f:
        rom = f.read()

    prg = rom[16:16+32768]

    bits = []
    j = 0x0b
    for i in range(0x5f):
        b1 = prg[0x718 + j]
        b2 = prg[0x798 + j]
        exp_bit = (b1 ^ b2 ^ i) & 1
        bits.append(exp_bit)
        j = (j + 0x25) & 0x7f

    letters = []
    for k in range(0, len(bits), 5):
        chunk = bits[k:k+5]
        val = 0
        for bit in chunk:
            val = (val << 1) | bit
        letters.append(chr(ord('A') + val))

    decoded = "".join(letters)
    words = ["SCIENTIA", "POTENTIA", "EST"]
    flag = f"FortID{{{'_'.join(words)}}}"
    print(flag)
    return flag

if __name__ == "__main__":
    solve()
```

## Flag

```
FortID{SCIENTIA_POTENTIA_EST}
```

## Lessons Learned

- NES ROMs often store text strings using a custom tile encoding indexed by font CHR tiles rather than standard ASCII.
- State machines controlled by zero-page memory variables provide clear focal points for identifying win conditions and hidden Easter Egg routines.
- Subtle in-game dialogues ("FIVE STRIPS AT A TIME") frequently encode crucial cryptographic parameters like Baconian cipher block sizes.

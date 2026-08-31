# Backrooms - Reverse Engineering Writeup

## Challenge Overview
- **Category:** Reverse Engineering
- **Points:** 304 (15 solves)
- **Description:** 'I saw a place' — Flag format is `COMPFEST18{UPPERCASE/DIGITS/ASCII_SYMBOLS_SEPARATED_BY_UNDERSCORES}`
- **Files Provided:** `rev_backrooms_x86-64-Windows.zip` containing `rev_backrooms.exe` (PE32+ 64-bit Windows executable) and 3D assets (`assets/backrooms/*`).

## Analysis
1. **Binary Identification:**
   Inspecting strings in `rev_backrooms.exe` revealed that it was written in Rust using the **Bevy** game engine (v0.19.0) and **Avian3D / Parry3D** physics engine (`parry3d-0.27.0`).
   Panic and error metadata identified custom code originating from `src/main.rs`.

2. **Reconnaissance & Cross-References:**
   Examining the `.pdata` section identified 90 custom user functions at the beginning of `.text` (`0x140001000` to `0x140008000`).
   The startup system located at `0x140003d30` sets up the game scene. Within this function at `0x140005276`:
   - An array of 60 bytes located at `.rdata` address `0x142f3f978` is loaded.
   - An LCG PRNG is initialized with seed `0xa3f1924d`, using parameters `next_seed = seed * 0x41c64e6d + 0x3039`.
   - For each byte `i` (from 0 to 59):
     - `b = (ciphertext[i] + r9b) & 0xff` (where `r9b` starts at `0xdb` and increments by `0xf3` mod 256 each round).
     - `b` is rotated right (ROR) by `(i % 7) + 1` bits.
     - `b` is XORed with the upper byte of the PRNG state (`(seed >> 16) & 0xff`).
     - The 8 bits of `b` (from MSB to LSB) are unpacked into memory.
   - The resulting `60 * 8 = 480` bits form a 4-row by 120-column grid.
   - The game iterates through this 4x120 grid and spawns 3D blocks (meshes) in the backrooms map for every bit equal to 1.

3. **Flag Recovery:**
   Extracting and decrypting the 60 bytes yields the 4x120 bitmap. Visualizing the grid reveals 30 glyphs formatted in a 3x4 dot-matrix font:
   ```text
   .##.###.##..###.###.###..##.###.##...##...#.#.#.###.....###..##.....##...#......#.#.###.###.###..##.....###.#...##..#...
   #...#.#.###.#.#.#...##..##...#...#..###.##..###.##.......#..##.......##.#.#.....#.#.##..#.#.#.#.##......#.#.#...#.#..##.
   #...#.#.#.#.###.##..#.....#..#...#..#.#..#..#.#.#........#....#.....#...#.#......#..#...###.##....#.....#.#.#...#.#..#..
   .##.###.#.#.#...#...###.##...#..###.###...#.#.#.###.###.###.##..###.###..#..###..#..###.#.#.#.#.##..###.###.###.##..#...
   ```
   Parsing the glyphs character by character gives:
   `COMPFEST18{HE_IS_20_YEARS_OLD}`

## Flag
`COMPFEST18{HE_IS_20_YEARS_OLD}`

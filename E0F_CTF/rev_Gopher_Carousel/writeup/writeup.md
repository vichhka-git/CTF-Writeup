# Gopher Carousel - Writeup

## Challenge Overview
- **Category:** Reverse Engineering
- **File:** `gopher-carousel.exe` (64-bit Windows PE compiled with Go)
- **Flag Format:** `e0f{...}`

## Analysis

1. **Intake & Symbol Extraction**:
   - Analyzed the Go pclntab at offset `0xe01e8` (Go 1.20 format).
   - Extracted main package functions:
     - `main.main` (`0x1400a7dc0`)
     - `main.q7` (`0x1400a7c80`)
     - `main.q4` (`0x1400a7ae0`)
     - `main.q3` (`0x1400a7900`)
     - `main.step` (`0x1400a7420`)
     - `main.rotateRing` (`0x1400a72a0`)
     - `main.ringCells` (`0x1400a6fe0`)
     - `main.q2` (`0x1400a6da0`)

2. **Algorithm Reconstruction**:
   - **Input Validation**: `main.main` expects a 41-character string `e0f{...}` containing a 36-character inner payload (6x6 grid of bytes).
   - **Target Generation (`main.q7`)**: Generates a 36-byte target array using SplitMix64 PRNG seeded with `0x6c617a795f677269` and static data at `0x140188d80`.
   - **Input Permutation (`main.q4`)**: Applies an initial permutation `dst_idx = (i * 5 + 7) % 36` with SplitMix64 XOR keying.
   - **State Transformations (`main.q3` / `main.step`)**: Applies 52 operations generated pseudorandomly by `main.q2`:
     - Op 0: `rotateRow` (circular row rotation)
     - Op 1: `rotateCol` (circular column rotation)
     - Op 2: `swapRows`
     - Op 3: `swapCols`
     - Op 4: `xorRowCol` (XOR mask with 8-bit rotations)
     - Op 5: `transpose`
     - Op 6: `rotateRing` (circular shift along concentric 6x6 rings)

3. **Inversion**:
   - Every operation has an exact, easily computed inverse (and `main.step` natively supported inverse execution mode).
   - We reversed the 52 steps starting from the `q7(2)` target grid.
   - Inverted the initial permutation and SplitMix64 XOR to recover the flag payload.

## Flag
`e0f{r0t4t3_th3_gr1d_4nd_c4tch_th3_g0ph3r}`

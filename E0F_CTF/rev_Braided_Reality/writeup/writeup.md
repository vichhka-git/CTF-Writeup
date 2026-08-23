# Braided Reality - Writeup

## Overview
- **Category:** Reverse Engineering
- **Target:** `braided_reality` (64-bit ELF executable)
- **Flag:** `e0f{braided_vm_semantics_not_guesses}`

## Analysis

### 1. Integrity and Input Format Checks
- Binary validates integrity of the `.brvm` section using CRC32 (`0x9eb3e508`).
- Checks argument format: `e0f{<32 characters>}` with all inner characters matching `[a-z0-9_]`.

### 2. Stage 1: First 16 Bytes Validation
- The first 16 inner bytes (128 bits) are verified against 128 linear equations over GF(2).
- Each equation tests: `popcount(mask0 & qword0) ^ popcount(mask1 & qword1) == target_bit`.
- Using Gaussian elimination over GF(2), we recover the first 16 bytes: `braided_vm_seman`.

### 3. Stage 2: Custom Bytecode VM
- The first 16 bytes combined with a 16-byte salt from `.brvm` (`0x20b0`) are hashed using 64-bit FNV-1a to initialize a 64-bit xorshift PRNG.
- 527 VM instructions (16 bytes each) are encrypted with the PRNG keystream starting at offset `0x28d4`.
- Decrypting the bytecode reveals an 8-register 64-bit VM:
  - 512 `BIT_XOR_MASK` operations conditional on input bits.
  - Circular rotations (`ROL_REG`), XORs (`XOR_REG`, `XOR_IMM`), and bit masks.
- The entire VM logic computing `(R0, R1)` is affine over GF(2) with respect to the remaining 128 unknown bits of the input.
- Solving the 128x128 linear system over GF(2) against the expected `(R0, R1)` constants at `0x49c4` yields the second 16 bytes: `tics_not_guesses`.

## Flag
`e0f{braided_vm_semantics_not_guesses}`

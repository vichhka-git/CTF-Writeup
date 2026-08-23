# Parallax Engine - Reverse Engineering Writeup

## Challenge Overview
- **Category:** Reverse Engineering
- **Binary:** `parallax-engine.exe` (Windows x86_64 PE, Go binary)
- **Description:** "The verdict existed before your answer did."

## Static & Symbolic Analysis
By parsing Go symbols via pclntab, we located custom functions in the `main` package:
- `main.main` (0x1400a77e0): Main entry point and input validation.
  - Expects a 53-character flag starting with `e0f{` and ending with `}` (48-byte inner string).
  - Verifies all 48 inner bytes are ASCII printable.
  - Computes a selector hash index: `(byte[0]*3 + byte[1]*5 + byte[2]*7 + byte[3]*11) & 3 = 2`.
  - Encodes the 48-byte input using `main.q4`.
  - Compares the 64-byte result against the output of `main.q7(2)`.
- `main.q7` (0x1400a76e0): Computes the target hash by applying PRNG stream `main.q5` to a precomputed table in `.data` at `0x1401880a0`.
- `main.q4` (0x1400a7400):
  - Applies a SplitMix64 PRNG XOR and permutation `(17 * rcx + 11) % 48` to the 48 input bytes.
  - Packs the 48 bytes into 6 uint64s, appends two constant uint64s `[0x566715150d283122, 0x1e285bbfdbd791ca]` to form an 8-element state array.
  - Invokes `main.q3` (a custom VM).
- `main.q2` (0x1400a6da0): Generates a deterministic table of 192 instructions (each 40 bytes).
- `main.q3` (0x1400a7080):
  - Executes initial XORs with rotation.
  - Executes 192 VM instructions supporting 6 opcodes (add+rotate, xor+rotate, rotate, modular multiply by odd constant, swap, Feistel-like ARX round).
  - Executes final permutation, XOR, and rotation.

## Inversion & Flag Recovery
Every single step in `main.q3` and `main.q4` is a bijective permutation:
1. `main.q3` final rotation/XOR/permutation is inverted directly.
2. The 192 VM instructions are inverted in reverse order:
   - Op 0: subtract rotated value.
   - Op 1: XOR rotated value.
   - Op 2: rotate right.
   - Op 3: multiply by modular inverse modulo $2^{64}$.
   - Op 4: swap registers.
   - Op 5: invert Feistel structure (XOR state[rdi] first, then subtract state[rsi]).
3. Initial XORs are inverted.
4. The resulting 8 uint64s match the constant trailer words `0x566715150d283122` and `0x1e285bbfdbd791ca`.
5. The first 6 uint64s are unpacked into 48 bytes, the position permutation `(17*i + 11) % 48` is inverted, and SplitMix64 keystream bytes are XORed back.

## Flag
`e0f{the_scheduler_hides_what_sleeping_gophers_forget}`

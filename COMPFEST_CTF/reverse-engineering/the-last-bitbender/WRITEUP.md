# The Last Bitbender - Writeup

## Challenge Overview
- **Category:** Reverse Engineering
- **Challenge ID:** 20
- **Target Binary:** `chall.exe` (3,072 bytes PE32 executable)

## Analysis & Vulnerability / Architecture Details
1. The binary `chall.exe` is a 32-bit Windows PE executable that performs a self-test in `main` (0x401000) on a 0x2a2-byte shellcode buffer stored in `.data`.
2. The shellcode demonstrates a classic **Heaven's Gate** technique (switching between 32-bit x86 and 64-bit x86_64 modes via `far jmp` / `far ret` using segment selectors 0x23 / 0x33).
3. The shellcode is composed of 4 alternating stages where each stage decrypts the next stage using an LCG / PRNG before executing it:
   - **Stage 1 (64-bit):** Decrypts Stage 2 using a 64-bit LCG. Loads 16 bytes of input as two 64-bit integers `A` and `B`, XORs `A ^= 0xa6f1c0d93b5e2748`, then switches to 32-bit mode.
   - **Stage 2 (32-bit):** Calculates `A = (A + (A & 0xffffffff) * (B & 0xffffffff)) & 0xffffffffffffffff`, `B = rol64(B, 13)`, and `A ^= B`. Decrypts Stage 3 with a 32-bit LCG, then switches to 64-bit mode.
   - **Stage 3 (64-bit):** Performs `B = (B + A) & 0xffffffffffffffff`, `B = rol64(B, 29)`, `B = (B * 0xff51afd7ed558ccd) & 0xffffffffffffffff`, `A = (A + B) & 0xffffffffffffffff`, `A = rol64(A, 17)`. Decrypts Stage 4 with a 64-bit LCG, then switches to 32-bit mode.
   - **Stage 4 (32-bit):** Computes output `out[0..7] = A ^ B` and `out[8..15] = (A + B) & 0xffffffffffffffff`.

4. The remote service sends a 16-byte hex challenge and expects the computed 16-byte response from this forward transformation.

## Solve
Running the Python solver against the remote service computes the forward transformation on the received hex string and retrieves the flag.

## Flag
`COMPFEST18{0nly_th3_av4t4r_m4st3r3d_4ll_th3m_b1ts_zWjEdHDUhv0RwMYu}`

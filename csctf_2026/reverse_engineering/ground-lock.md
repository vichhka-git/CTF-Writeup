# Ground Lock

**Category:** Reverse engineering · **Points:** 120 · **Flag:** `CSCTF{HALCYON_1B5FC6D72036689A}`

## What the handout gives you

The handout contains a single statically linked x86-64 Linux executable:

- `fcunlock` (682,600 bytes, SHA-256 `9634a7c4c4769a21eb921125a3d1b0ef560e3f4ed0202efa860861f0d2922399`) — ground-maintenance unlock utility for the flight controller.

## Walkthrough

1. **Inspect binary properties and entry point.** Running `file fcunlock` identifies an ELF 64-bit LSB executable, statically linked and stripped. Disassembling with `objdump -d fcunlock` or loading into a decompiler reveals standard runtime initialization calling into a compact verification function at `main`.

2. **Analyze input validation.** The binary prompts for a service code on standard input. It checks that the supplied input string is exactly 24 bytes in length, followed by a newline or null terminator. It then treats the 24 bytes as an array of three 64-bit little-endian words: `w0`, `w1`, and `w2`.

3. **Reverse the hashing algorithm.** Each 64-bit word passes through an identical bit-mixing transformation before comparison:
   - `x ^= x >> 33`
   - `x = (x * 0xff51afd7ed558ccd) & 0xffffffffffffffff`
   - `x ^= x >> 33`
   - `x = (x * 0xc4ceb9fe1a85ec53) & 0xffffffffffffffff`
   - `x ^= x >> 33`

   This sequence is MurmurHash3's 64-bit finalizer (`fmix64`). The transformation is a bijection over the 64-bit integers.

4. **Locate the reference constants.** The hashed words are compared sequentially against three 64-bit constants stored in the read-only data section:
   - `target0 = 0x8bfd351846ffb86b`
   - `target1 = 0x3ff3fd892aa7e3b2`
   - `target2 = 0xf61e79e7e639e0d2`

5. **Invert the finalizer steps.** Because `fmix64` is an invertible permutation, each step can be undone in reverse order:
   - Inverting `x ^= x >> 33`: because the shift amount (33) exceeds half the word size (32), the shifted bits cannot affect higher bits, meaning `inv_shift(y) = y ^ (y >> 33)`.
   - Inverting the 64-bit multiplications: calculate the modular multiplicative inverse of the multipliers modulo `2^{64}`:
     - `pow(0xc4ceb9fe1a85ec53, -1, 2**64) = 0x9cb4b2f8129337db`
     - `pow(0xff51afd7ed558ccd, -1, 2**64) = 0x4f739b6beb753341`

6. **Recover the plaintext blocks.** Applying the inverse function to each stored target constant reveals the original 64-bit values:
   - `inv_fmix64(0x8bfd351846ffb86b) = 0x5f4e4f59434c4148`
   - `inv_fmix64(0x3ff3fd892aa7e3b2) = 0x3744364346354231`
   - `inv_fmix64(0xf61e79e7e639e0d2) = 0x41393836363032`

7. **Decode the byte strings.** Unpacking each 64-bit integer into 8 bytes little-endian produces printable ASCII text:
   - Block 0: `b"HALCYON_"`
   - Block 1: `b"1B5FC6D7"`
   - Block 2: `b"2036689A"`

   Concatenating the three blocks reconstructs the 24-character unlock sequence `HALCYON_1B5FC6D72036689A`.

## Answer

Passing `HALCYON_1B5FC6D72036689A` into `fcunlock` outputs the authorization confirmation. Wrapping the service code in the flag wrapper yields:

`CSCTF{HALCYON_1B5FC6D72036689A}`

## Notes

The binary contains thousands of library functions due to static linking, but the actual validation code occupies less than 60 assembly instructions in `main`. Recognizing the constants `0xff51afd7ed558ccd` and `0xc4ceb9fe1a85ec53` immediately identifies MurmurHash3's `fmix64` function, making brute force unnecessary.

# Uplink Denied

**Category:** Reverse engineering · **Points:** 200 · **Flag:** `CSCTF{cau_reset_09ff4472cbe8e0}`

## What the handout gives you

The handout provides a single Linux x86-64 executable representing the satellite command-authentication unit:

- `cau_verify` (682,600 bytes, SHA-256 `19fc211ceda00357c70c5039dd882f11491c8bfb092b15824bc13f2bdc84990c`) — statically linked, stripped ELF executable.

## Walkthrough

1. **Locate the entry point and input verification.** Disassembling the binary shows the entry point at `0x401650`, which passes `0x4014f0` as the main routine to `__libc_start_main`. Inspecting `0x4014f0` reveals an immediate check on `argc == 2`. If an argument is present, the program passes `argv[1]` to `strlen` and asserts that the string length is exactly 24 bytes (`0x18`). Any other length prints usage instructions and exits with status 1.

```sh
objdump -d --start-address=0x4014f0 --stop-address=0x401640 cau_verify
```

2. **Map the data chunking.** The binary loads `argv[1]` as three consecutive 64-bit little-endian words:
   - Word 0 at `argv[1] + 0x00`
   - Word 1 at `argv[1] + 0x08`
   - Word 2 at `argv[1] + 0x10`

3. **Identify the hash permutation.** Each 64-bit word is passed through the same sequence of bitwise shifts and 64-bit integer multiplications. The structure matches the SplitMix64 finalizer:
   - `x ^= (x >> 33)`
   - `x = (x * 0x9df50ad53e8f1c7b) & 0xffffffffffffffff`
   - `x ^= (x >> 33)`
   - `x = (x * 0xc17a4b92d6e30f55) & 0xffffffffffffffff`
   - `x ^= (x >> 33)`

4. **Extract the expected target values.** The transformed words are compared against three 64-bit constants:
   - Word 0 is compared with `0xd8dba78e270f595d`
   - Word 1 is compared with `0x25d4e9834acb3349`
   - Word 2 is compared with `0x976a0bc7e24f7338`

   When all three match, execution branches to `0x40161a` and prints the success banner.

5. **Invert the transformation stages.** Because the right shift is 33 bits on a 64-bit register, the upper 33 bits remain unchanged by the XOR. Applying the operation a second time cleanly undoes the first: `(x ^ (x >> 33)) ^ ((x ^ (x >> 33)) >> 33) == x`. Both constants `0x9df50ad53e8f1c7b` and `0xc17a4b92d6e30f55` are odd, meaning they are coprime to `2^{64}`. Their multiplicative inverses modulo `2^{64}` exist and can be computed directly:
   - Multiplicative inverse of `0x9df50ad53e8f1c7b` modulo `2^{64}` is `0x6e9f90cf94e09fbb`.
   - Multiplicative inverse of `0xc17a4b92d6e30f55` modulo `2^{64}` is `0xb480112cb95368a5`.

   Reversing the operations step by step maps any 64-bit target back to its original preimage:
   - `y ^= (y >> 33)`
   - `y = (y * 0xb480112cb95368a5) & 0xffffffffffffffff`
   - `y ^= (y >> 33)`
   - `y = (y * 0x6e9f90cf94e09fbb) & 0xffffffffffffffff`
   - `y ^= (y >> 33)`

6. **Recover the plaintext key.** Feeding the three target constants into the inverse routine produces:
   - `0xd8dba78e270f595d` yields `0x657365725f756163`, which unpacks in little-endian order to `cau_rese`.
   - `0x25d4e9834acb3349` yields `0x3434666639305f74`, which unpacks to `t_09ff44`.
   - `0x976a0bc7e24f7338` yields `0x3065386562633237`, which unpacks to `72cbe8e0`.

   Combining these three 8-byte chunks in order reconstructs the 24-byte recovery key `cau_reset_09ff4472cbe8e0`.

## Answer

Passing the 24-byte key to the binary verifies the unlock code, producing the flag `CSCTF{cau_reset_09ff4472cbe8e0}`.

## Notes

Because 33 is strictly greater than half of 64, the shift-XOR step is self-inverting. No linear system or bitwise SAT solving is required.

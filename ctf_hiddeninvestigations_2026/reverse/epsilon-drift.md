# Epsilon Drift

Reverse, 54 points, 556 solves (author Hidden Investigations). A stripped gfortran binary
takes one argument, a hex-encoded calibration vector of four doubles, and prints the run
config it releases. The vector has to satisfy integer constraints on the raw bit patterns,
one gate that only checks that a double equals zero, and one exact floating-point sum.

## What you are given

`epsilon-drift.zip` expands to `extracted/epsilon-drift`, 1,232,784 bytes, statically
linked, stripped, non-PIE, built with gfortran. The only interface is
`./epsilon-drift <hexvector>`. There is no live service and no login material.

## Reproduction

1. Identify the build and the two entry points. `file` reports a statically linked,
   stripped, non-PIE executable, and the strings contain the usual gfortran runtime
   messages. `main` is 0x401d30 and the program body is `MAIN__` at 0x401f10.

2. Read the argument handling at the top of `MAIN__`. It calls `GET_COMMAND_ARGUMENT`
   (0x408820) and requires the returned length to be exactly 0x40, so the argument is 64
   hex characters decoded to 32 bytes. Those bytes are four little-endian doubles in
   order: v0, v1, v2 and v3.

3. Gate A is at 0x4020ad. It is `ucomisd` against 0.0 followed by `jp` and `jne`, so v3
   only has to compare equal to zero. That comparison cannot tell +0.0 from -0.0.

4. Gate B at 0x402180 compares the raw 64 bits of `v0 + v1` with the bits of v2, and also
   requires that neither v0 nor v1 has its sign bit set. v2 must therefore be the exact
   IEEE-754 sum of v0 and v1.

5. Gate C is a chain of window comparisons on the bit patterns of v0 and v1. Four
   13-bit windows (shifts 0, 13, 26 and 39) and the exponent field (masked with 0x7ff)
   are each checked twice, and all ten checks are ANDed together:

   ```
   (L0 + L1)   & 0x1fff = 0x1334    (L0 + 2*L1)   & 0x1fff = 0x0cce
   (M0 + M1)   & 0x1fff = 0x1998    (M0 + 2*M1)   & 0x1fff = 0x0664
   (H0a + H1a) & 0x1fff = 0x0ccc    (H0a + 2*H1a) & 0x1fff = 0x1332
   (H0b + H1b) & 0x1fff = 0x0666    (H0b + 2*H1b) & 0x1fff = 0x0999
   (e0 + e1)   & 0x07ff = 0x07ff    (e0 + 2*e1)   & 0x07ff = 0x03ff
   ```

   Each pair solves to one value modulo the window size: L = 6554, M = 3276,
   H_a = 1638, H_b = 819, e0 = 1023, e1 = 1024. Those are the windows of 1.1 and 2.2:

   ```
   v0 = 1.1          = 0x3ff199999999999a
   v1 = 2.2          = 0x400199999999999a
   v2 = 1.1 + 2.2    = 0x400a666666666667   (3.3000000000000003, not 3.3)
   ```

   The `residual 3.300000000000000e+00 WARN rounding` line in the description is the hint
   that the third double is the exact sum, not the decimal literal 3.3.

6. Set v3 to negative zero, bit pattern 0x8000000000000000. Gate A passes, because
   `ucomisd` reports -0.0 equal to +0.0. Then the success path at 0x402291 runs
   `movq %xmm1, %rax; testq %rax, %rax; movl $1, %eax; cmovsl %eax, %esi`, so the sign
   flag of the raw pattern sets the mode register to 1 and the config decryptor runs.
   With +0.0 the mode stays 0 and the program takes the rejection branch instead; that
   message is 33 bytes at `.rodata` 0x4e34a0 XOR 0x6b, and it is the text
   `calibration residual out of band`.

7. Assemble the vector as four little-endian doubles and hex-encode it:

   ```
   9a9999999999f13f 9a99999999990140 6766666666660a40 0000000000000080
   ```

8. Feed it in. The recorded run used an amd64 container because the workstation is arm64:

   ```sh
   ./epsilon-drift 9a9999999999f13f9a999999999901406766666666660a400000000000000080
   # hiCTF{1eee754_s1gn3d_z3r0_1u1p_dr1ft_eps!}
   ```

9. Check the decryptor so the result does not rest on one run. Mode 1 at 0x402a70
   computes `d = SHA256(input32)`, then builds a counter stream
   `SHA256(d || be32(0)) || SHA256(d || be32(1))`, and XORs 42 bytes of the table at
   `.rodata` 0x4e3500 with it. Those 42 bytes are exactly the flag:

   ```
   table 3bbeb4bf04778c23156b6a73e19c6bee1af9de15d3785cbbe7f9cc5ac6981f018a76a7de499969a7895e
   plain hiCTF{1eee754_s1gn3d_z3r0_1u1p_dr1ft_eps!}
   ```

## Why it works

The vector is not searched for, it is solved. The ten window equations fix every field of
both doubles, and the exact-sum gate then fixes the third. The flaw is in the fourth
value. The validator's zero test uses a floating comparison, which treats -0.0 and +0.0 as
equal, while the code that decides whether to decrypt reads the sign bit of the same
double. Negative zero slips through the check and lands in the success branch, so the
difference between the two zeros, which most languages quietly erase, is the whole
challenge.

## Flag

```
hiCTF{1eee754_s1gn3d_z3r0_1u1p_dr1ft_eps!}
```

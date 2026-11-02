# Obfuscated Flow

Reverse, 55 points, 466 solves (author `otolk1`). A stripped 18,440-byte ELF asks for one
47-character passkey, spreads the 40 body characters over ten little-endian dwords, and
checks them in five independent two-word groups. Each group is a different small arithmetic
problem, and together they pin the exact passkey, which in turn drives the keystream that
prints the flag.

## What you are given

`rev-obs-flow.zip` expands to one binary, `challenge`, 18,440 bytes, ELF64 little-endian,
stripped, dynamically linked. The archive digest in the README is
`ddaca1f93d3f748482982814ed307b58f9fba73e6298bb4551594a2b344a2d30`; the extracted ELF is
`41518c8f469fba4e695a00fa66184e422447d604823f69f0d9b44b457f8eefc6`. There is no service.
It prints `=== [ hiCTF Sentinel Gateway ] ===`, `Passkey: ` and then either a banner or
`[-] Access Denied.`

The team's submission log records the derived passkey as accepted (`goodFlag`, 30 October
2026).

## Reproduction

1. Fix the input format first. `main` is at `0x4010c0`: it `fgets` 256 bytes into `rsp+0x170`,
   strips a trailing `\n` or `\r`, then requires the remaining length to be `0x2e`, which
   means 47 characters. It compares the first six bytes with the string at `0x403046`
   (`hiCTF{`) and checks that byte 46 is `}`. So the body is `input[6:46]`, exactly 40 bytes,
   read as ten little-endian dwords `x0..x9`.

2. Look at the arithmetic block that follows at `0x4011be..0x4014ed`. It reads overlapping
   dwords out of the `hiCTF{`-stripped string and mixes them with large constants
   (`0x7a69` = 31337, `0xcc1321` = 13374241, `0x3ade68b1` = 987654321, `0x3b9aca07` =
   1000000007, plus the moduli 2147483647 and 4294967291) and stores the results on the
   stack. A control-flow-flattened dispatcher then routes between check blocks by comparing
   a 32-bit state word against constants held in rodata at `0x4030e0`. That table is six
   32-byte rows whose first dwords are `0x6b3e91f2`, `0x19c45d80`, `0x43b7e025`, `0x51e29f3a`,
   `0x3d087b16`, `0x38a5f41c`; the rest of each row is the filler pattern
   `00,11,22,33,44,55,66`. Any branch that does not land on a check block reaches
   `[-] Access Denied.`

3. Write the checks as five pairs, with `P = 2147483647`, `E = 1000000007` and
   `F = 4294967291`:

   | words | constraint |
   |---|---|
   | x0,x1 | x0^2 - 31337*x1^2 = 0x1e054920 and x0*x1 = 0x37c0f52c, mod P |
   | x2,x3 | 1337*G + (x2 mod E, x3 mod E) = (0x2d0c1bbd, 0x205c7191) on y^2 = x^3 + 133742x + 0x30730db7 mod E, G = (123456789, 239241263) |
   | x4,x5 | 7^(x4 mod P-1) = 0x7bb949ec and 11^(x5 mod P-1) = 0x0b3bbfc8, mod P |
   | x6,x7 | 13374241*x6 + 987654321*x7 = 2456158549 and 123456789*x6 + 555666777*x7 = 2108140227, mod F |
   | x8,x9 | x8 + x9 = 0x4770c967 and x8*x9 = 0x2e97d196, mod P, plus x8 xor 9 and x9 xor 17 must be prime |

   The second row is worth reading twice: the curve point is `1337*G` plus the input point,
   not 1337 times the input point. An earlier reading of this block got the direction wrong
   and produced no candidate.

4. Solve each pair with the method its shape suggests, then lift every solution to readable
   bytes by adding multiples of the modulus until all four bytes of the dword are printable
   ASCII. That filter is what collapses each pair to one answer.

   - Pair 0: substitute `x0 = D * y^-1` into the first equation and you get a quadratic in
     `y^2` modulo a prime that is 3 mod 4, so square roots are one exponentiation. Recorded
     result: `(1752446061, 1848664927)`.
   - Pair 1: compute `1337*G = (40007916, 948148196)` and subtract it from the target, giving
     the input point `(815114349, 812410463)`. Lifting x2 gives
     `(1815114356, 812410463)`.
   - Pair 2: two baby-step giant-step discrete logs with `m = isqrt(P-1) + 1`. Recorded
     logs `[1815306103, 1953509740]`.
   - Pair 3: this pair really is linear, a 2x2 system modulo `F`. Gaussian elimination gives
     RREF `[[1,0,1683972913],[0,1,1600614252]]`.
   - Pair 4: sum and product give a quadratic; the primality conditions on `x8 xor 9` and
     `x9 xor 17` fix the order. Recorded result `(1647797812, 1698259762)`.

5. Pack the ten words little-endian. They read `m4th`, `_c0n`, `tr0l`, `_fl0`, `w_3l`,
   `l1pt`, `1c_d`, `log_`, `4f7b`, `2c9e`, which is the passkey
   `hiCTF{m4th_c0ntr0l_fl0w_3ll1pt1c_dlog_4f7b2c9e}`. It is 47 characters, matching the
   input check.

6. Model the output stage rather than trying to patch around it. The buffer is 98 bytes,
   `out[i] = rodata[0x31a0 + i] xor keystream[i]`. The PRNG is seeded from 32 bytes at file
   offset `0x3210`: `0x0123456789abcdef`, `0xfedcba9876543210`, `0x89abcdef01234567`,
   `0x76543210fedcba98`. Its round at `0x401f80` is eight repetitions of add, rotate
   (13, 16, 32, 17, 21, 32) and xor over four 64-bit lanes.

7. Apply the five seed mixes in order, each followed by one PRNG round: `x0<<32 | x1`,
   `0x2d0c1bbd205c7191` (the EC target), `0x7bb949ec0b3bbfc8` (the two discrete-log targets
   concatenated), `0x926601557da7aac3` (the linear system's constant vector), and
   `x8<<32 | x9`. Then run the PRNG once more before each 32-byte block of output. Missing
   that extra refresh is what made an earlier model decrypt to noise.

8. Check the gate. The binary computes `acc = 0; for b in out: acc = (acc*31 + b) mod 2^32`
   and compares against `0xb4f079c8`, then `printf("%s")`. Re-running the model above returns
   `0xb4f079c8` and the text `[+] ACCESS GRANTED! Passkey verified.` followed by the flag
   line, so the model and the binary agree on the constants.

9. What is not recorded: the discarded roots and the size of the discrete-log tables. The
   derivation notes print only the accepted printable lifts, and there is no captured
   terminal session of the original binary accepting the passkey. The accepted submission is
   the end-to-end confirmation.

## Why it works

Every pair is a different small problem, and none of them is large enough to resist textbook
methods: a 31-bit prime, a 32-bit prime, a curve over a 1e9+7 field, two 31-bit discrete logs
and one 2x2 linear system. The dwords are interpreted little-endian over printable ASCII, so
the modulus lift of each residue has only one readable candidate. The checksum does not hide
anything either; it only decides whether the buffer is printed, and the buffer is a fixed
rodata table XORed with a keystream that depends on the ten words. Recover the words and the
banner appears by itself.

## Flag

```
hiCTF{m4th_c0ntr0l_fl0w_3ll1pt1c_dlog_4f7b2c9e}
```

# Night Batch

Reverse, 56 points, 437 solves. A stripped 392,008-byte Linux ELF carries a GnuCOBOL
runtime and validates an 18-digit account key through 23 modular arithmetic checks, then
derives a SHA-256 keystream that decrypts a 42-byte message. The COBOL source and copybooks
did not survive, so the checks have to be read out of compiled field arithmetic.

## What you are given

`night-batch.zip` expands to one file, `night-batch`, 392,008 bytes, ELF64 little-endian,
non-PIE, stripped, entry `0x400980`, build-id `04dd085be7caef7b53b4876989949592c301406f`.
It needs only `libc.so.6` and `libm.so.6` and embeds the GnuCOBOL and GMP runtimes. The
interface is a single argument, `./night-batch <account-key>`. There is no live service.

The team's submission log records this challenge as solved from the portal before the
submission gate existed, so no `goodFlag` response exists for it. The derivation below comes
from the local workspace notes; the keystream, plaintext and digest were re-checked against
the binary while writing this up.

## Reproduction

1. Identify the toolchain before reading any logic. `strings -n 8 night-batch | grep -i cob`
   returns `cob_set_runtime_option`, `cob_free`, `COB_CORE_FILENAME` and
   `/usr/share/gnucobol/config`, and the binary also carries GMP. The checks are therefore
   COBOL `PIC` field operations lowered to helper calls, not hand-written C comparisons.

2. Find where the argument lands. The main validator at `0x400a70` compares the length field
   at `0x460130` against `0x12` (18), runs a numeric class check through `0x404bc0`, then
   loops at `0x400c97..0x400d11` moving 18 one-character fields from `0x460140+i` into
   `0x460100+i` with `cob_move` (`0x40f900`). So `d[i]` lives at `0x460100 + i` and the key
   must be exactly 18 decimal digits.

3. Read one check block in full. It is the same shape 23 times:

   ```sh
   objdump -d --start-address=0x400d13 --stop-address=0x400da0 extracted/night-batch
   ```

   The block sets `esi = 0x2a` (multiply) and calls `0x41df30`, then loads the divisor
   literal at `0x44cdf0` and calls `0x41e530`, moves the result into the packed field
   `0x45e360` via `0x411de0`, compares with `0x413920` against the immediate `8`, and jumps
   to the shared failure path `0x400b77` on inequality.

4. Take the truncation seriously, because it is the whole puzzle. `0x41e530` is a
   three-instruction thunk (`xor edx,edx; jmp 0x41d740`) that pushes the value through a
   packed field whose width comes from the literal it is handed. Checks 1 to 22 pass `'10'`
   at `0x44cdf0` and check 23 passes `'100'` at `0x44cd30`. The compared value is therefore
   `expr mod 10`, or `expr mod 100` for the last check, not `expr`. A first attempt that
   treated the immediates as exact equality came out unsatisfiable for this reason alone.
   A second trap was an AR/CHK trace read out of order, which made a check appear to compare
   against the wrong number.

5. Recover the 23 equations. `d_p` is the p-th key digit, 0-based, and every coefficient is
   non-negative with no constant term:

   | # | expression | expected |
   |---|---|---|
   | 1 | (d1*d10) % 10 | 8 |
   | 2 | (d3+d4+d8) % 10 | 3 |
   | 3 | (3*d2+d3+2*d4+3*d5+d6) % 10 | 1 |
   | 4 | (d2+d10+d17) % 10 | 7 |
   | 5 | (3*d5+d6+2*d7+3*d8) % 10 | 7 |
   | 6 | (3*d8+d9+2*d10+3*d11) % 10 | 7 |
   | 7 | (3*d11+d12+2*d13) % 10 | 9 |
   | 8 | (d0+3*d14+d15+2*d16+3*d17) % 10 | 2 |
   | 9 | (d0+d11+d17) % 10 | 7 |
   | 10 | (d6+d10+d14) % 10 | 6 |
   | 11 | (d7+d9+d14) % 10 | 2 |
   | 12 | (d0+d13+d17) % 10 | 3 |
   | 13 | (d7+d8+d12) % 10 | 2 |
   | 14 | (d0+2*d1+3*d2+2*d16+3*d17) % 10 | 2 |
   | 15 | (d12+2*d13+3*d14) % 10 | 5 |
   | 16 | (d0+d12+d13) % 10 | 5 |
   | 17 | (2*d7+3*d8+d9+2*d10) % 10 | 1 |
   | 18 | (3*d5+d6+2*d7) % 10 | 9 |
   | 19 | (d12+2*d13+3*d14+d15) % 10 | 4 |
   | 20 | (d4+d5+d16) % 10 | 4 |
   | 21 | (d1*d9) % 10 | 4 |
   | 22 | (d0+d4+d8) % 10 | 0 |
   | 23 | (4*d3+5*d6+5*d10+2*d15+9*d16) % 100 | 94 |

   The digit pointer table at `0x44cf00` looks like an input permutation but is only the
   evaluation order: it holds `0x460100 + {10,1,3,8,4,6,5,2,17,7,9,11,12,13,15,16,14}`.

   ```python
   for p in range(0x4cf00, 0x4cf88, 8):
       print(struct.unpack_from('<Q', b, p)[0] - 0x460100, end=' ')
   ```

6. Solve the system over digits `0..9`. z3 finds exactly one solution,
   `481702596318740925`. The notes also record a black-box route that reaches the same model
   without transcribing the disassembly: copy the binary, NOP the 22 `jne` branches, force
   the failure path after check 23, hook `0x413920` and `0x41df30` with an `LD_PRELOAD`
   logger, then evaluate the 23 outputs at `K=0`, at every unit vector `e_p` and at every
   pair `e_p + e_q`. That is 172 sampled keys, which is enough to fit the quadratic
   coefficients exactly; the fit predicted 276 of 276 values on 12 fresh random keys.

7. Model the gate at `0x402f40`. `digest = SHA256(key)` over the 18 bytes, the keystream is
   `SHA256(digest || BE32(0)) || SHA256(digest || BE32(1))`, and 42 bytes of ciphertext are
   XORed with it. The ciphertext table starts at `0x44d0c0`, file offset `0x4d0c0`. The load
   at `0x403000` is `movzbl 0x44d0bf(%rdi,%rax)` with `rax` starting at 1, so the first byte
   read is `0x44d0c0`; taking the displacement as the table base shifts the whole plaintext by
   one byte. The plaintext is accepted only when `SHA256(P)` equals
   `bd3f6ab64668142c88e427a5ef541618dbea3a32f68fbc6d8fa0f6aeef80a6b0`.

8. Confirm the answer. Reading the 42 bytes at file offset `0x4d0c0` and XORing them with
   the keystream from `SHA256(b"481702596318740925")` yields
   `hiCTF{c0b0l_p4ck3d_d3c1mal_n1ghtly_b4tch!}`, and SHA-256 of that plaintext is exactly
   the digest embedded in the binary. Running `./night-batch 481702596318740925` prints the
   same string.

9. What the notes do not record: the original portal submission (it predates the gate), the
   number of candidates z3 enumerated before uniqueness, and the raw hook log behind the
   172 sampled keys. Only the fitted model and the validation counts are kept.

## Why it works

The check is 23 modular equations over 18 decimal digits. The only subtlety is that the
compiler's numeric field conversion truncates each expression to the declared picture width,
so the constants in the code are residues rather than values. A modular system that small
pins a single key. The message itself is never stored in the clear: it is XORed with a
SHA-256 keystream keyed by the account key, and the binary hashes its own plaintext, so a
wrong key cannot produce a plausible flag.

## Flag

```
hiCTF{c0b0l_p4ck3d_d3c1mal_n1ghtly_b4tch!}
```

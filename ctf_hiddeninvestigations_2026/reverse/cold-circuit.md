# Cold Circuit

Reverse, 68 points, 170 solves (author Hidden Investigations). A standalone checker
called `check` decides whether a flag is right. There is no service, the input is one
line, and the whole validator is 20 rounds of byte arithmetic over a 16-byte state
compared against a fixed target.

## What you are given

`cold-circuit.zip` expands to `extracted/check`, 14,472 bytes, x86-64 PIE, stripped,
dynamically linked against libc (`fgets`, `puts`, `strlen`, `memcmp`, `ptrace`). It reads
the candidate from `argv[1]` when present, otherwise one line from stdin. There is no
live service and no login material.

## Reproduction

1. Start with the strings, because they tell you what the checker can say.

   ```sh
   strings -a extracted/check | grep -E 'hiCTF|input|format|reachable|granted|Incorrect'
   # hiCTF{  no input  Bad format.  unreachable  Access granted.  Incorrect.
   ```

2. Disassemble the input routine at 0x12d6. It strips trailing `\n` and `\r`, then
   requires the length to be exactly 0x27, the first six bytes to be `hiCTF{` (compared
   against the string at 0x2290), and the last byte to be `}`. Anything else exits
   through `Bad format.`.

3. The same routine decodes 16 bytes from the 32 characters at offsets 6 and 7, 8 and 9,
   and so on. The hex helper at 0x1283 accepts 0 to 9, a to f and A to F and returns -1
   for anything else, so the body has to be exactly 32 hex characters. That is the first
   trap: the ASCII payload `n0_jtag_needed!!` is rejected before the cipher runs.

4. Read the cipher between 0x1623 and 0x1748. Twenty rounds, each with three steps over
   the 16-byte state:

   ```
   state[i] = (state[i] + roundkey[16*r + i]) & 0xff
   state[i] = sbox[state[i]]
   out[perm[i]] = state[i]
   ```

   The tables sit at the front of `.rodata`: the 256-byte S-box at 0x2020, the 16-byte
   permutation at 0x2120, 20 round keys (320 bytes) at 0x2140, and the 16-byte target at
   0x2280. The loop bound at 0x173f is `cmpl $0x13`, so it is 20 rounds.

5. Dump the tables and check their sizes, since the inverse depends on the S-box being a
   permutation of 0 to 255 and on the permutation being a bijection of 0 to 15.

   ```sh
   objdump -s -j .rodata extracted/check | sed -n '/^ 2020/p;/^ 2120/p;/^ 2280/p'
   ```

   The permutation is `0a 08 04 0e 06 07 03 00 09 05 01 0d 0f 0b 0c 02` and the target
   is `976714880a500d160a21f6950eef3481`. Round key 0 is
   `8dc4d82953eeab8725e95b51094ba8d7` and round key 19 is
   `5b56751fbc7cf79cd973d73a6cd726e4`.

6. Invert the rounds from 19 down to 0. Undo the permutation first, then the S-box, then
   the key addition:

   ```
   a[i] = b[perm[i]]
   a[i] = inv_sbox[a[i]]
   a[i] = (a[i] - roundkey[16*r + i]) & 0xff
   ```

   The result is the 16-byte payload `6e305f6a7461675f6e65656465642121`, which reads as
   ASCII `n0_jtag_needed!!`. Running the forward transform on it reproduces the target
   byte for byte.

7. Notice that the accepted text is not that ASCII. The checker compares the decoded 16
   bytes against the target, but the string it consumes is hex, so the flag body is the
   hex encoding of the recovered state, 32 characters. The candidate is `hiCTF{` plus
   those 32 characters plus `}`.

8. Confirm it against the real binary. The workstation is arm64, so the recorded run used
   an amd64 container:

   ```sh
   echo 'hiCTF{6e305f6a7461675f6e65656465642121}' | ./check
   # Access granted.
   ```

   Feeding the decoded ASCII body instead ends in `Bad format.`, and any 39-character
   string with a wrong hex body ends in `Incorrect.`.

9. Read the two dead branches before trusting a decompiler. The helper at 0x1229 returns
   true when `x*x % 4 == 2` and the helper at 0x125c returns true when
   `(x*x + 1) % 4 == 0`; a square is 0 or 1 modulo 4, so neither condition can ever hold.
   They are wired to exit with 98 and to print `unreachable` and exit with 99. Neither
   path can ever be taken. The `ptrace(PTRACE_TRACEME)` call at 0x1533 fails harmlessly
   when a tracer is present: it stores errno and complements two bytes of the state
   buffer, then continues.

## Why it works

The 20-round transform is an invertible byte network with its S-box, permutation and
round keys stored in `.rodata` in the clear, and the comparison is against a fixed
16-byte target. Nothing depends on the input, so the transform runs backwards as easily
as forwards. The only real obstacle is the presentation: the checker accepts the hex
encoding of the recovered state rather than the state itself, so the ASCII that falls
out of the inverse is a step, not the answer.

## Flag

```
hiCTF{6e305f6a7461675f6e65656465642121}
```

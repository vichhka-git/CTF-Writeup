# The Inner Engine

Reverse, 57 points, 356 solves. A 40,000-byte stripped Nim binary validates a 24-byte
activation key inside a 234-instruction bytecode VM, then uses SHA-256 in counter mode to
unseal a 40-byte record. The key is never stored anywhere, so the only way in is to recover
the VM's constraint program and solve it.

## What you are given

`inner-engine.zip` expands to one file, `inner-engine`, 40,000 bytes, ELF64 little-endian,
stripped, dynamically linked. The archive digest in the README is
`8c20991917e05093d0c87268ae9563515cd33abc90dd36b916413b5667559f46`. The interface is one
argument, `inner-engine <key>`, which either prints the unsealed activation record or the
message `license sealed`. There is no service. The team's submission log records the
recovered key and flag as accepted (`goodFlag`, 31 October 2026).

## Reproduction

1. Identify the language and notice that the domain strings are missing. `strings` shows
   `syncio.nim`, `cmdline.nim` and `paramStr`, which is Nim with its standard argument
   handling. The failure text does not appear at all: it is stored XORed with `0x3c` at
   `0x406298`, and only that decode reveals it.

   ```python
   d = open('inner-engine','rb').read()
   print(bytes(b ^ 0x3c for b in d[0x6298:0x62a8]))
   # b'license sealed\n'
   ```

2. Follow the argument. `main` at `0x400530` saves argv and calls the Nim entry at
   `0x4048eb`, which takes `paramStr(1)`, requires its length to be exactly `0x18` (24 bytes),
   and then runs the dispatch loop at `0x404709` over 234 five-byte records starting at
   `.rodata 0x405e00`. Each record is `opcode:u8, immediate:u32le`, so the program text is
   1,170 bytes.

3. Confirm the record layout before trusting any decode. In this non-PIE layout the file offset
   is the VA minus `0x400000`, so slicing 1,170 bytes at `0x5e00` and taking every fifth byte
   gives 234 opcodes whose first entry is `0xf2` (anti-debug), last entry is `0x0b` (unseal),
   20 distinct values, and 61 records that load a key byte.

4. Recover the handler map. The initialisation routine at `0x404588` stores handler
   addresses such as `0x403c14`, `0x403c1c` and `0x403c64` into 8-byte slots in `.bss`
   around `0x40a240`, and the dispatch loop indexes that table with the record's opcode.
   Matching slots to handler code gives the instruction set. The entries the checker relies
   on are:

   | opcode | meaning | opcode | meaning |
   |---|---|---|---|
   | 0x17 | push immediate | 0x49 | jump if zero |
   | 0x4c | push key[i] | 0xd7 | jump |
   | 0x95 | push local[i] | 0x1e | equal |
   | 0x38 | store local[i] | 0x7d / 0xc1 / 0x8a | add / sub / mul |
   | 0x52 | xor | 0x33 / 0xbf | and / or |
   | 0x64 | rotate left | 0xcc | shift left |
   | 0xf2 | anti-debug (TracerPid) | 0x0b | unseal |
   | 0x5a / 0xe5 | halt | | |

5. Translate the program. The VM pushes four local copies of `key[0..3]`, then runs 23 byte
   comparisons against values built from other key bytes, then reaches the unseal opcode.
   Every arithmetic result is truncated to 8 bits:

   | key bytes | condition (mod 256) |
   |---|---|
   | key[5] xor key[6] | 84 |
   | key[9] + key[10] | 164 |
   | key[10] + key[11] | 190 |
   | key[12] + key[13] | 159 |
   | key[13] + key[14] | 153 |
   | key[14] + key[15] | 148 |
   | key[16] + key[17] | 148 |
   | key[17] + key[18] | 154 |
   | key[18] + key[19] | 155 |
   | key[19] + key[20] | 153 |
   | key[20] + key[21] | 154 |
   | key[22] + key[23] | 150 |
   | key[23] + key[0] | 177 |
   | key[3] * key[15] | 67 |
   | key[7] * key[21] | 236 |
   | key[11] * key[19] | 83 |
   | key[0] xor key[8] xor key[16] | 33 |
   | key[4] xor key[12] xor key[20] | 65 |
   | key[2] xor key[10] xor key[18] | 54 |
   | key[0] + key[4] + key[8] + key[12] + key[16] + key[20] | 154 |
   | key[1] xor key[5] xor key[9] xor key[13] xor key[17] xor key[21] | 86 |
   | key[2] + key[7] + key[10] + key[15] + key[18] + key[23] | 1 |
   | key[3] xor key[6] xor key[11] xor key[14] xor key[19] xor key[22] | 119 |

6. Solve the system. z3 over 24 byte variables gives a single assignment,
   `L1c#N0d3_7mQ9f3a2b8c6d1e`. Every one of the 23 rows above evaluates to zero for that
   key when the operations are taken modulo 256, which was re-checked while writing this up.

7. Model the unseal routine at `0x404416`. `seed = SHA256(key)`, the keystream is
   `SHA256(seed || BE32(0)) || SHA256(seed || BE32(1))`, and the 40 bytes at `0x4062e0` are
   XORed with it. Acceptance is `SHA256(record)` equal to the 32 bytes at `0x4062c0`. The
   SHA-256 core is `0x404004` (standard IV at `0x406420` and K at `0x406320`) and the counter
   expansion is `0x404336`.

8. Check the recorded constants against that model. The digest at file offset `0x62c0` is
   `e4f870dad765bfab3d282870ec136b8f450dc8c606cd894b9ea78c91736a5272`, which is exactly
   `SHA256` of the 40-byte flag. The ciphertext at `0x62e0` is
   `9a40bd7dd28fe31997a3de379af40bd87d815f4413fdbd86100c465179799c4202f983c0d7974e1c`,
   and XORing it with the keystream from the recovered key gives the same 40 bytes.

9. Run the binary with the key and with a one-byte variant to see both paths:

   ```
   $ ./inner-engine 'L1c#N0d3_7mQ9f3a2b8c6d1e'
   hiCTF{vm_byt3c0d3_1nn3r_3ng1n3_unw0und!}
   $ ./inner-engine 'L1c#N0d3_7mQ9f3a2b8c6d1f'
   license sealed
   ```

10. Leave the anti-debug alone. Opcode `0xf2` is the first instruction and reads
    `/proc/self/status` for `TracerPid`, which gates the VM before any key handling. Static
    analysis never triggers it. Tracing is a dead end for a different reason: the key arrives
    in `argv` and the binary never stores it, so the only stored artifacts are the ciphertext
    and the plaintext digest.

11. What the notes do not record: the meaning of the three record opcodes that do not appear in
    the table above (`0x2b`, `0x6e`, `0xa3`), how many z3 models were enumerated, and any
    transcript from the anti-debug path.

## Why it works

A bytecode VM is still a program. The handler table is initialised in one place, so the
instruction set can be recovered by matching slots to code, and the program text is a plain
array of fixed-size records in `.rodata`. Once the records are read, the checker is 23 byte
constraints that a solver closes immediately. The key is not embedded anywhere because the
author made the input the key to a SHA-256 keystream and authenticated the decrypted record
with its own hash, so there is no comparison constant to lift and no plaintext to find. The
record is exactly 40 bytes and the flag is 40 characters, so the unsealed record is the answer
itself.

## Flag

```
hiCTF{vm_byt3c0d3_1nn3r_3ng1n3_unw0und!}
```

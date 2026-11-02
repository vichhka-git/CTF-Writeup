# Titan Relay

Pwn, 66 points, 190 solves. A Windows console program runs under Wine behind a TLS socket and
offers one real feature: load a capsule. The capsule is hex, is XOR-decoded with a fixed keystream,
and is then executed as bytecode by a small interpreter the banner calls the route consensus vm. A
router gate inside the VM validates a capsule struct against a random per-run key and hands it to a
validator that decrypts a path and opens it. The bug is the signed index range on the VM's store
instruction, which lets a capsule write into the VM object's prefix and forge exactly the fields
the gate checks.

## What you are given

`titan-relay.zip` expands to:

```
titan_relay.exe     286,208 bytes, PE32+ x86-64, Rust, stripped
run_titan.sh        socat wrapper, runs the exe as user ctf
Dockerfile          ubuntu:24.04 with wine, wine64 and socat
docker-compose.yml  tmpfs for the Wine prefix, flag copied to /flag.txt
flag.txt            hiCTF{fake_flag_for_local_testing}
```

The portal supplies `<challenge-host>` and `<port>`; the console is TLS wrapped. No login material.

The console is small:

```
=== TITAN RELAY :: route consensus vm ===
1) load capsule
2) quit
Option > 
```

Option 1 asks `Capsule length > ` and `Capsule hex > `, then answers `[+] capsule accepted` or
`[!] capsule rejected`. The loader takes a length of 1 to 512 and at least twice that many hex
characters, and the interpreter stops after 0x200 instructions.

## Reproduction

1. Find the decode. The hex bytes are XORed with a fixed keystream before execution, with no other
   transformation: `ks[i] = (0x71 + 0x3d*i) & 0xff`. Everything below is written as plaintext
   bytecode and then XORed with that stream.

2. Map the dispatcher. The interpreter reads the next byte at `0x1400035ac`, tests the range
   0x71..0xb1 and jumps through the signed-relative table at `0x14003c164`; otherwise it tests
   0x21..0x51 and uses the table at `0x14003c0a0`; 0x11 is handled separately; anything else faults
   at `0x140003c6c`. A short disassembly pass decodes every slot, and the table holes are
   listed in the local opcode map.

3. Write down the opcodes that matter. `R[i]` is the register bank at object offsets 0x18..0x50 and
   `M[i]` is the memory bank at 0x58..0xd0:

   | op | operands | effect |
   |---|---|---|
   | 0x11 | reg, imm32 | `R[b1] = imm32` |
   | 0x21 | reg, idx16 | `R[b1] = M[index]`, index 0..15 |
   | 0x32 | reg, i16 disp, lane | `*(u32*)(S+0x58+8*disp+4*lane) = low32(R[b1])` |
   | 0x41 | reg, imm32 | `R[b1] ^= imm32` |
   | 0x42 | dst, src | `R[b1] ^= R[b2]` |
   | 0x71 | dst, cmp, slot | if `R[b2] == S+0xd8` then `R[b1] = [S+0xd8+8*slot]`, slot 0..2 |
   | 0x81, 0x82 | reg, n | `R[b1] <<= n`, `R[b1] >>= n` |
   | 0xa3 | reg, i16 | `R[b1] += i16` |
   | 0xa4 | dst, src | `R[b1] += R[b2]` |
   | 0xb1 | dst, src | `R[b1] = R[b2]` |
   | 0x51 | none | router gate, described in step 5 |

4. Note the hole in 0x32. The handler compares the signed index with -10 using `jge`, then with 15
   and skips if greater, so the accepted range is -10..15. Negative indexes write before the memory
   bank, into the object prefix, and `lane` selects the low or high 32-bit half. The offsets that
   matter are disp -10 for S+0x08, -9 for S+0x10, -8 for S+0x18, -7 for S+0x20, -6 for S+0x28, -5
   for S+0x30 and -2 for S+0x48. Every write stays inside the 0xf8-byte allocation.

5. Read the gate at 0x51 (`0x140003b26`). It computes `[S+8] ^ [S+0]` and `[S+0x10] ^ 0x1400018c0`,
   ORs the two, and fails if the result is nonzero. It then loads `rcx = [S+0x48]` and fails if that
   is zero. On success it calls `0x1400018c0` with `rcx` pointing at the struct. The validator
   compares the struct key with the run key, XOR-decrypts an 11-byte order with that key and opens
   the result as a path. No menu option reaches the validator, so the gate opcode is the only way
   in, and the capsule has to satisfy it from inside the VM.

6. Work out the key material. The state object S is 0xf8 bytes. The loader fills S+0x00 with the
   run key (derived from `GetSystemTimePreciseAsFileTime` and a heap address), S+0x58 with
   `&S+0xd8` (which is also M[0]), S+0xd8 with the low 32 bits of the key, S+0xe0 with the high 32
   bits, and S+0xe8 with the key XOR the validator address. A `0x21` with register 4 and memory index
   0 loads `&S+0xd8` into R[4], and a `0x71` whose comparison register is 4 matches
   `R[b2] == S+0xd8` and copies the three special qwords into registers. That is the capsule's only
   way to learn the key.

7. Forge the struct in the register bank at S+0x18. The validator expects, at the pointer the gate
   passes in `rcx`:

   ```
   +0x00  key      u64, must equal the run key
   +0x08  payload  pointer to the ciphertext, use S+0x68
   +0x10  cap      high32 = 11, low32 = (key >> 32) ^ low32(key)
   +0x18  len      low32 = low32(cap) + low32(key)
   ```

   The key halves come from the `0x71` loads. The validator address is recovered as
   `S+0xe8 ^ key`; with the default image base `0x140000000` the validator sits at `0x1400018c0`
   and the high dword is 1, while the low dword still comes from the leaked XOR value, which is
   what keeps the capsule independent of the per-run key.

8. Write the order. The payload is 11 bytes, `Z:\flag.txt` XOR the key, stored as three dwords with
   0x32 at disp +2 (both lanes) and disp +3 (low lane), which is S+0x68, S+0x6c and S+0x70. The
   plaintext dwords before the XOR are `0x665C3A5A`, `0x2E67616C` and `0x00747874`, and the top byte
   of the third one leaves the terminating NUL at S+0x73.

9. Set the gate fields with the same store: S+0x08 gets the key (two stores at disp -10), S+0x10
   gets the validator address (disp -9), and S+0x48 gets `&S+0x18` (disp -2). End the capsule with
   0x51.

10. Send it. The capsule in the local workspace is 207 bytes, 414 hex characters, well inside both
    limits. Load it with option 1, give the length, then the hex. The recorded live run prints:

    ```
    [+] capsule accepted
    hiCTF{ru5t_vm_g4te_and_h4ndler_ch41n_2d6eec5715}
    ```

11. What the notes do not record: the per-run key and the module base of the accepted run. Both are
    recovered inside the capsule (`S+0xd8`/`S+0xe0` and `S+0xe8 ^ key`), so the payload does not
    need them, but no transcript of the accepted run's values was kept. An earlier local
    result still says parked; the accepted record is the local writeup and the submission entry
    from 31 October 2026.

## Why it works

The gate compares three fields that live in the same object the bytecode can write. The key is not
a secret from the VM: it sits in clear at S+0xd8 and S+0xe0, and the XOR'd validator pointer at
S+0xe8 hands back the validator address. So the check reduces to "did you copy the key into the
right places", which the bytecode can do with a handful of instructions.

The negative range on the store is what makes the prefix writable at all. The handler rejects
indexes above 15 and forgets to reject anything below -10, and the object layout puts the integrity
fields, the register bank and the memory bank in one allocation, so a store aimed at the memory
bank can reach the header the gate reads. The validator then does exactly what it was written to
do: it decrypts the order with the key it was given and opens the path.

## Flag

```
hiCTF{ru5t_vm_g4te_and_h4ndler_ch41n_2d6eec5715}
```

# Snapfile

Reverse, 59 points, 298 solves. A stripped Crystal binary, `snaptool`, validates a container
format its authors invented and never documented, then decrypts a 46-byte label that it treats
as the flag. No sample `.snap` ships with the challenge, so the format has to be read out of
the binary and a valid container built by hand.

## What you are given

`snapfile.zip` expands to one file, `snaptool`, 586,736 bytes, ELF64 little-endian, stripped,
dynamically linked against glibc and `libcrypto.so.3`. The archive digest in the README is
`33ba2e74970adb7f6f25c9b6a85eae326b2e7b5724c09e71fad6ed7a28f51eb6`. The interface is a single
argument, `./snaptool somefile.snap`, and the only diagnostics are the label on success and
`invalid snapfile` on any failure. There is no service. The team's submission log records the
reconstructed container as accepted (`goodFlag`, 31 October 2026).

## Reproduction

1. Find the one domain string. `strings -n 8 snaptool` yields only `invalid snapfile`, plus
   the Crystal and OpenSSL markers. Crystal keeps string literals as rodata headers of the
   form type id, byte size, character length, then the bytes, so the header sits at
   `0x461f70`: `01 00 00 00`, `10 00 00 00`, `10 00 00 00`, then the text at `0x461f7c`.
   Following the two references to it (`0x4035e4` and `0x403bc2`) lands in the inlined
   validator, which is the whole program.

2. Write down the header the validator insists on. All multi-byte header integers are
   big-endian:

   | offset | size | value | check |
   |---|---|---|---|
   | 0x00 | 4 | `SNAP` | byte compares |
   | 0x04 | 2 | `00 02` | `movzwl` then `rolw 8` equals 2 |
   | 0x06 | 1 | `03` | immediate |
   | 0x07 | 1 | `00` | immediate |
   | 0x08 | 8 | `SNAP-LNG` | assembled big-endian equals `0x534e41502d4c4e47` |
   | 0x10 | 4 | 40 | equals 0x28 |
   | 0x14 | 4 | 16 | equals 0x10 |
   | 0x18 | 4 | 56 | equals 0x38 |
   | 0x1c | 4 | 32 | equals 0x20 |
   | 0x20 | 4 | 88 | equals 0x58, the end of the second section (56 + 32) |
   | 0x24 | 4 | 8 | equals 0x08 |
   | 0x28 | 56 | payload | section boundaries at 40+16, 56+32 and 88+8 |
   | 0x60 | 8 | checksum | big-endian 64-bit |

   The total file length must be exactly `0x68`, which is 104 bytes.

3. Reproduce the checksum. It covers bytes `0x08` through `0x5f`, starts from a fixed
   constant, mixes each byte with a multiplication and a shift-xor fold, and the stored value
   is the fold XOR 0x58:

   ```python
   acc, M = 0x1357bdf02468ace1, (1 << 64) - 1
   for b in data[8:0x60]:
       r = ((b + acc) & M) * 0xd1b54a32d192ed03 & M
       acc = r ^ (r >> 29)
   assert int.from_bytes(data[0x60:0x68], 'big') == acc ^ 0x58
   ```

4. Build the container. Take the 40 fixed header bytes, fill the 56-byte payload with zeros,
   and append the 8-byte checksum from step 3. The build that passed here is 104 bytes with
   checksum `0xfd47ab989124f3f2`, and the loop in step 3 recomputes that value from the file.

5. Decrypt the embedded label. The key material is the header alone:

   ```python
   seed = hashlib.sha256(data[:40]).digest()
   ks = b''.join(hashlib.sha256(seed + i.to_bytes(4, 'big')).digest() for i in range(2))
   label = bytes(a ^ b for a, b in zip(cipher, ks))
   ```

   The 46-byte ciphertext is not contiguous in the binary. It is assembled at `0x401eb9`
   from the 32 bytes at `0x45d740`, then the immediates `movabs 0x94D42DD9E83F07E3`,
   `movl 0x141EDD40` and `movw 0x1478`:

   ```
   8c5cd458ca615ca021018cdefbb2407818c4c2a9be8d5a19d3412caaaccb3d5de3073fe8d92dd49440dd1e147814
   ```

6. Sanity-check the label against the binary's own gate. It computes `SHA256(label)` and
   compares it with the 32 bytes at `0x45d760`:
   `11c9700fd68fbef2d6ed848fab3a80613908c6aa16640e3e9404419bcdc80028`. The decrypted label
   hashes to exactly that, so the label is the intended value, not a partially decrypted
   buffer. Reading the 32 bytes at file offset `0x5d760` confirms the constant.

7. Run the tool. It needs glibc 2.38 or newer and `libcrypto.so.3`, so the recorded run used
   an Ubuntu 24.04 container, which prints the flag and exits 0:

   ```sh
   docker run --rm --platform linux/amd64 -v "$PWD:/w" -w /w ubuntu:24.04 \
     sh -c 'apt-get update -qq && apt-get install -y -qq libssl3t64 >/dev/null; \
            ./snaptool genuine.snap'
   ```

8. What the notes do not record: what the three payload sections are meant to contain. Nothing
   in the path that was read compares their contents, so zeros are accepted and the fixed
   header is enough. The origin of the header constants, beyond the immediate compares, is not
   documented anywhere in the challenge directory.

## Why it works

The container has no signature and no secret. Its integrity check is a custom 64-bit fold
that anyone can implement, and the label key is derived from the first 40 bytes, which are
fixed constants the validator itself dictates. So "genuine" is a property you can construct:
write the required header, compute the checksum, append it, and the tool accepts the file.
The binary then verifies `SHA256(label)` against a constant before printing, which proves the
decrypt used the right key and turns the reconstruction into a confirmation rather than a
guess.

## Flag

```
hiCTF{r3c0nstruct3d_th3_sn4pf1l3_by73_by_by73}
```

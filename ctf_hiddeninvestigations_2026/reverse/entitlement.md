# Entitlement

Reverse, 59 points, 296 solves (author Hidden Investigations). A licence checker asks for
a serial and an activation code, then prints a subscription message. The file is a
self-extracting loader, the checker behind it hides its bytecode, the activation check is
an elliptic curve discrete log on a badly chosen curve, and the last stage is a
deliberately enormous loop that collapses to a single exponentiation.

## What you are given

`entitlement.zip` expands to `extracted/Entitlement`, 15,048 bytes, statically linked
x86-64 ELF with no section headers. There is no live service and no login material.

## Reproduction

1. Look at the load layout before running anything. `readelf -h -l` reports entry
   0x40abd8, five program headers and no section headers. PT_LOAD #0 covers vaddr
   0x400000 with filesz 0x1000 but memsz 0x7220; PT_LOAD #1 covers vaddr 0x408000 with
   filesz 0x37d9 and aliases the same file bytes. The entry point sits at file offset
   0x2bd8.

2. Run it. It dies with SIGTRAP (exit 133) before printing anything, with or without an
   argument. The entry code is hand written: `memfd_create("bld")`, a range decoder that
   decompresses an embedded image into the memfd, `mmap` of that descriptor as
   read/execute, then `execveat`. The failure paths use `hlt`, which is the trap that is
   observed.

3. Get the inner ELF out. The workspace keeps a ptrace dump harness and the unpacked
   artifact; the notes describe the marker repair as the route that produced it. The
   packer magic `UPX!` was overwritten with `HI4!` at file offsets 0x19c, 0x3a9a and
   0x3aa4. Restoring those three dwords makes UPX 5.3.0 accept the file and unpack it
   into a 27,224-byte stripped dynamically linked ELF.

4. Stage 1, the serial. The unpacked program prints `Serial >` and takes exactly 16 hex
   characters. The value passes through a 99-instruction bytecode VM whose bytecode lives
   at virtual address 0x407080, encrypted with a key derived from a hash of the 418-byte
   `vmtext` and the TracerPid. Decoding the bytecode shows five shift and XOR blocks that
   compute

   ```
   a = serial ^ 0xd1705c3b2e33689b
   VM(serial) = a^13 ^ 0xba6b1f3cb925c25a   in GF(2)[x] / (x^64 + 0x2b395c2099596d9f)
   ```

   The check wants `VM(serial) == 0x30cefbec2e4bc466`. Because gcd(13, 2^64 - 1) = 1 the
   map is a bijection and inverts with one exponentiation:

   ```
   a^13   = 0x30cefbec2e4bc466 ^ 0xba6b1f3cb925c25a = 0x8aa5e4d0976e063c
   a      = (a^13)^(13^-1 mod 2^64-1)              = 0x5e0dedb0f93d71a0
   serial = a ^ 0xd1705c3b2e33689b                  = 0x8f7db18bd70e193b
   ```

   The real binary accepts that serial and advances to `Activation code >`.

5. Stage 2, the activation code. It takes 25 hex characters, so up to 100 bits, and uses
   the value as a scalar: the code must satisfy `d*P == Q` on

   ```
   p = 0x8c817b4a4c0f170cd5aab18cf
   a = 0x65561c079c3bb669feb4d54d9
   b = 0x3905920c79c2f7ace28164fb6
   P = (0xc217d88d4bf005f2022d4e0f, 0x30999f70fb48e2b703431f4d0)
   Q = (0x622d01f78ebad9c83dd402304, 0x387932a13c1ef33f165880b6)
   ```

   PARI's `ellcard` returns exactly p = 695750960437370813140792187087 for this curve, so
   it is anomalous and the Smart attack applies. The recorded run lifts P and Q to
   E(Z/p^2), multiplies in Jacobian coordinates so no division by a multiple of p appears,
   and reads the formal parameter `t = -X*Z/Y`, which is divisible by p:

   ```
   d = (t_Q/p) * (t_P/p)^-1 mod p = 0x2977e17b118de75b3b4e921a4
   ```

   `d*P == Q` verifies in ordinary affine arithmetic over the same curve.

6. Stage 3, the loop. The derivation builds a 2040-bit input from
   `SHA256(serial_le64 || act_lo_le64 || act_hi_le64 || i)` for i from 0 to 7, with the
   top byte of the 256-byte digest block cleared. It then runs an outer loop of 50,000
   calls to an inner loop of 10,000, so 500,000,000 Montgomery multiplications. Probing
   that routine to identify it (the gcd of `out(a,b) - a*b*out(1,1)` over several inputs)
   recovers a 2048-bit modulus g at 0x405540, and the constant at 0x405440 turns out to be
   `R^2 mod g` with `R = 2^2048`. The first call enters Montgomery form, the loop squares,
   the last call leaves, so

   ```
   out = input^(2^500000000) mod g
   ```

   g is composite with no small factors, so the exponent cannot be reduced modulo a group
   order. Reimplementing the loop with GMP's `mpz_powm` took 267 s in the recorded run.

7. Turn the loop output into the flag. With `prefix` the 24 bytes above and `out_le` the
   256-byte little-endian result:

   ```
   h1      = SHA256(prefix || out_le)
   derived = SHA256(h1 || i)[0:8] for i = 0..7
   flag    = table[0x405200 .. 0x405240] XOR derived
   ```

   The binary's own final check is that the 64 derived bytes sum to 0x133d, and they do.
   The notes record the sum check and the flag string; they do not say what the trailing
   11 bytes of that 64-byte buffer contain.

8. Validate the stage 3 model before trusting the long run. A copy of the unpacked binary
   with the loop counters patched to 1 and the final sum check NOPed printed exactly the
   64 bytes the model predicts for n = 1. The local notes record that comparison as
   byte-for-byte, which is what makes the n = 500,000,000 result safe to trust.

## Why it works

Three mistakes stack. The VM hides its bytecode but not its algebra: the transform is a
fixed XOR key followed by a power map, and the exponent 13 is coprime to 2^64 - 1, so the
serial is one exponentiation away. The curve has #E = p, which makes the discrete log
polynomial instead of hard. The 500-million-operation loop is repeated squaring modulo a
fixed number, so the same work done with a bignum library took 267 s, and the loop output
feeds a short SHA-256 chain that ends in a 16-bit sum check.

## Flag

```
hiCTF{>o<_C0ngrats_Her3_1s_Y0ur_HI4_Subscript1on_^_^}
```

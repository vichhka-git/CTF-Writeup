# Cold Beacon

Reverse, 54 points, 617 solves (author Hidden Investigations). One stripped Linux binary
takes a 24-byte key and, if the key checks out, prints the configuration it was carrying.
The key check is a set of byte equations, and the configuration is XORed with a stream
derived from the key the user supplies, so the real gate is a SHA-256 over the recovered
plaintext.

## What you are given

`cold-beacon.zip` expands to `extracted/cold-beacon`, 40,000 bytes, stripped x86-64 ELF,
dynamically linked, built with Nim (`syncio.nim` and `cmdline.nim` appear in the strings).
Entry is 0x400560 and the load base is 0x400000, so file offset equals virtual address
minus 0x400000 for the loaded image. There is no live service and no login material.

The local workspace also holds patched copies of the binary, a 2,304-entry candidate key
list and a 296 KB search log; those are scratch and nothing below depends on them.

## Reproduction

1. Confirm the shape of the file and the absence of packing. `file` reports a 64-bit
   stripped executable. In the file, `.text` covers 0x530 to 0x451d and `.rodata` covers
   0x57e0 to 0x614f, and the recorded entropy is 5.07 bits per byte over the whole file
   and 5.45 over `.rodata`, so there is no second compressed stream to unpack.

   ```sh
   file extracted/cold-beacon
   ```

2. Run it with a wrong 24-byte key. It prints the sealed message and nothing else. That
   message is 14 bytes at 0x5e00 XOR 0x5a, and the stored bytes decode to the text
   `config sealed`. Main checks that exactly one argument was supplied and that its
   length is 24 before any comparison runs, so a short or long key never reaches the
   validator.

3. Disassemble main at 0x404271 and the validator at 0x403cff. The validator walks 23
   records out of four tables in `.rodata`:

   ```
   targets   0x5fa0   23 bytes
   indices   0x5fc0   23 records of 6 slots
   counts    0x6050   23 bytes
   types     0x6070   23 bytes
   ```

   Types 0 and 3 XOR the listed bytes, types 1 and 4 add them modulo 256, and type 2
   multiplies two bytes modulo 256. Each record's low byte is compared with its target,
   and the index byte 0xff is padding rather than an input.

4. Dump the tables and rebuild the records, with key bytes x0 to x23 in argument order.

   ```python
   d = open('extracted/cold-beacon','rb').read()
   tgt, idx, cnt, typ = d[0x5fa0:0x5fb7], d[0x5fc0:0x5fc0+138], d[0x6050:0x6067], d[0x6070:0x6087]
   ```

   For the accepted key the 23 records come out as follows (all arithmetic modulo 256):

   ```
   x5^x6=07    x9+x10=a8   x10+x11=74  x12+x13=e3  x13+x14=da  x14+x15=9c
   x16+x17=ce  x17+x18=a5  x18+x19=74  x19+x20=71  x20+x21=98  x21+x22=94
   x22+x23=99  x23+x0=a9   x3*x15=c0   x7*x21=83   x11*x19=24
   x4^x12^x20=00   x2^x10^x18=6c
   x1^x5^x9^x13^x17^x21=09   x3^x6^x11^x14^x19^x22=0f
   x0+x4+x8+x12+x16+x20=c4   x2+x7+x10+x15+x18+x23=d9
   ```

   Records 20 and 22 are type 5, six-byte XOR rows with targets 0x09 and 0x0f. The recon
   lists mode 5 as XOR like mode 0, while the search notes treat it as skipped by the
   validator. If it is skipped, x1 and x5 are unconstrained, and the accepted key
   satisfies both rows regardless.

5. Read the chains. Records 6 to 13 walk from x16 through x17, x18, x19, x20, x21, x22,
   x23 and close on x0, so those nine bytes follow from one choice of x16. Records 1 and
   2 give x11 and x9 from x10, and records 3 to 5 form a second chain through x12, x13,
   x14, x15 that needs one free byte. The rest tie the chains together: record 18 gives
   x2 from x10 and x18, record 15 gives x7 from x21, record 21 then gives x15, record 17
   gives x4, and record 19 gives x8. Record 14 and record 16 constrain x3 and x11 without
   fixing them, because 0xc0 and 0x24 are even.

6. Use the plaintext to settle the leftover freedom. The configuration blob is 47 bytes
   and the flag format is `hiCTF{`, so the first six keystream bytes are known:

   ```python
   ct = bytes.fromhex('62e8732e8602c5dd3c16a976ae2a8991d4a18ed112e7405fbfb1352674256bfffdfe12332534e3b3fc9581c945e0a6')
   prefix = bytes(a ^ b for a, b in zip(ct, b'hiCTF{'))    # 0a81307ac079
   ```

   The KDF is SHA-256 in counter mode: seed is SHA256(key), then the stream is
   SHA256(seed || be32(0)) followed by SHA256(seed || be32(1)) and so on, and 47 bytes
   need two blocks. A candidate key therefore has to satisfy

   ```python
   hashlib.sha256(hashlib.sha256(k).digest() + b'\x00\x00\x00\x00').digest()[:6] == bytes.fromhex('0a81307ac079')
   ```

   That 48-bit filter picks one key out of the remaining free bytes. It is the 24
   character ASCII string `C0ldB34c0n::unl0ck::7a3f`, hex
   `43306c6442333463306e3a3a756e6c30636b3a3a37613366`. Which free-byte values the search
   reached first is not recorded; the notes keep only the final key and the evidence
   command.

7. Decrypt the blob and check it. The ciphertext is 47 bytes at 0x5e40 and the expected
   digest is the 32 bytes at 0x5e20:

   ```
   0502f285cdf9105600a27444181c301609e2a30aaa7516c555f60802b066ad40
   ```

   SHA-256 of the recovered plaintext must equal it.

   ```python
   seed = hashlib.sha256(key).digest()
   pad  = hashlib.sha256(seed + b'\x00\x00\x00\x00').digest() + hashlib.sha256(seed + b'\x00\x00\x00\x01').digest()
   pt   = bytes(a ^ b for a, b in zip(pad, ct))
   ```

   The plaintext hashes to the stored digest and is exactly the flag, 47 bytes with no
   padding.

8. Run the binary to confirm. Do not use a debugger: the routine at 0x403aec reads
   `/proc/self/status` and rejects a nonzero `TracerPid:`. The recorded evidence command
   is `./cb "C0ldB34c0n::unl0ck::7a3f"`, and it printed the flag.

## Why it works

The key is checked by 23 byte-sized equations, so the licence gate is a constraint puzzle
rather than a cryptographic check. Two key bytes are not covered by the enforced rows,
and the configuration blob is XORed with a keystream derived from the same key the user
supplies. The plaintext's known prefix turns into a cheap filter that resolves the
leftover freedom, and the digest at 0x5e20 validates the output rather than the key,
which is why a candidate that satisfies the equations still has to decrypt correctly.

## Flag

```
hiCTF{c0ld_b34c0n_cfg_uns34l3d_fr0m_th3_s4mpl3}
```

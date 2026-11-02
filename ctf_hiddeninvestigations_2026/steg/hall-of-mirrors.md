# Hall of Mirrors

Steganography, 92 points, 80 solves. A 26 minute stereo field recording. The entry point
is a text panel drawn into the mid channel's spectrogram, and the payload is a keyed bit
stream in the low byte of the samples. What comes out is byte code for a small virtual
machine, and the machine emits an elliptic curve signature set whose nonces are short.
The chain ends with a lattice solve and a keyed stream cipher.

## What you are given

`hall-of-mirrors.zip` expands to `hall-of-mirrors.wav`, 299,520,216 bytes: PCM, 48 kHz,
stereo, 16 bit, 74,880,000 frames, exactly 1560.000 seconds.

The hint archive `archivist-datasheet.zip` expands to `archivist_datasheet.txt`, 49
lines. It specifies three formats: the MirrorStego v1 carrier schedule, the MVM1
instruction set, and the payload TLV with its key derivation and stream cipher. Without
that sheet the byte code and the unsealing step are not guessable, so this is a
specification-following challenge more than a guessing one.

There is no service and no login material.

## Reproduction

1. Confirm the container is ordinary before hunting inside it. The RIFF size field is
   299,520,208 and matches the file, `fmt ` is PCM with 2 channels at 48000 Hz, block
   align 4, 16 bits per sample, and the data chunk sits at 0xd8 with 299,520,000 bytes,
   ending exactly at EOF. The LIST INFO block names the file "Hall of Mirrors", the
   artist "atrium ensemble", the date 2026-02-14 and calls it a binaural pair at
   48k/16. There are no extra chunks, no padding byte and no trailing data.

2. Render the mid channel as a spectrogram. Take `mid = (L + R) / 2`, run an STFT with
   1024 or 2048 points, and look at 1180 to 1255 seconds between 5.8 and 14 kHz. Two rows
   of dot matrix glyphs appear. The side channel `(L - R) / 2` is blank in the same
   window, so the panel was mixed to the centre. The glyph rows sit on 28 tones spaced
   about 193.4 Hz apart, the character cells are 8 by 14 pixels, the column pitch is
   0.31998 s, and the text starts at grid column 3688, about 1180.2 s. It reads:

   ```
   MIRROR S1   SM64/GAP/PAR
   K=9C4F1E7A3B50D682
   ```

   One recorded correction matters here. The first pass read the key as
   `9C4F1E7A3B5CDE92`. Re-measuring on the exact 28 tone grid, where the key line
   occupies 20 cells with a two cell gap after `9C4F1E7`, gives
   `9C4F1E7A3B50D682`, and that is the value that extracts a CRC valid frame. Treat the
   panel as a labelled pointer, not as the payload; the label `SM64` sent several
   attempts after the wrong generator family before the datasheet named SplitMix64.

3. Apply section 1 of the datasheet to the sample data. Only the low byte of each
   interleaved int16 sample is used. SplitMix64 is seeded with the 64 bit key, the
   sample index starts at p = -1, and each hidden bit costs two draws: the first draw
   advances p by `1 + (draw_1 % 4096)`, the second supplies a mask
   `w = (draw_2 >> 17) & 0xFF`. The bit is the parity of the population count of the low
   byte XOR the mask. Bits are packed most significant first.

   ```python
   p += 1 + (draw1 % 4096)
   bit = bin(low_byte(data[p]) ^ ((draw2 >> 17) & 0xFF)).count("1") & 1
   ```

   With a mean step of 2048 samples, the frame touches a few tens of thousands of the
   149,760,000 samples, which is why nothing at the waveform or container level looks
   disturbed.

4. Read the frame header before decoding the body. It is 8 bytes of `MIRRORS1`, then a
   little endian u32 payload length of 6266, then a little endian u32 CRC of
   `0xe2046fb1`. The extraction consumes 50,256 bits, its last sample index is
   102,678,021, and it stops 68.6 percent of the way into the stream. Recomputing CRC32
   over the 6266 payload bytes gives `e2046fb1`, so the seed and the schedule are both
   confirmed. A wrong seed yields random bytes that do not spell `MIRRORS1`.

5. Parse the payload as an MVM1 image: magic `MVM1`, code length 6107, data length 143,
   entry point 0, reserved 0. The sixteen byte header plus 6107 plus 143 is exactly
   6266 bytes. The first code bytes are `3a 00 01 00 00 00 00 00 00 00`, which the
   datasheet decodes as IMM R0 with the immediate 1.

6. Execute the machine with the section 2 rules. It has 64 KiB of code and 64 KiB of
   data in separate spaces, sixteen u64 registers and a 256 entry stack. R15 starts at
   `0xCBF29CE484222325` and is rehashed on every instruction fetch with
   `R15 = ((R15 ^ opcode) * 0x100000001B3) mod 2^64` followed by `R15 ^= R15 >> 31`.
   The SMC opcode XORs a xorshift64 keystream into live code bytes, so a static
   disassembly is not sufficient. The recorded run halts after 20,395 instructions with
   an empty stack and has emitted 5,083 bytes, starting with `MIRRORS1`. The output hash
   is `dad158f3d263ecd648496035f5c009e6089806a8836281948fb50fbb68f2003e`.

7. Parse the emitted TLV, which is a second `MIRRORS1` header followed by typed records
   and a zero terminator at offset 5082 with no trailing bytes:

   ```
   01..06  curve parameters, 32 bytes each
   07      Q, 64 bytes
   08      L = 0x0c = 12
   09      count = 48
   0a      48 records of 96 bytes (z, r, s), 32 bytes each, big endian
   0b      sealed blob, 33 bytes
   ```

   Types 01 to 06 are secp256k1: n is
   `fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141`, p is
   `fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f`, a is 0, b is 7,
   Gx is `79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798` and Gy is
   `483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8`. Q is
   x `f5d07683ee055bd35c4de3f0b5ce2a04d65598ebaac584f2b32a1e7c813c2c2d`, y
   `6ba9329be937aae35a1b8d418ddf643a22e92bf954cfa169c3e21ec25b22784d`.

8. Notice the two decoy flags before going further. The data segment of the image is 143
   bytes at payload offset 6123, and it holds two printable strings that the machine
   never emits: `hiCTF{vm_h4lted_early}` at the start of the segment, and
   "Analysis complete. The flag is hiCTF{stop_here}. No further steps are required." at
   offset 6187. Both are bait for anyone who greps the payload instead of running it.
   This is the "every reflection points at another one" part of the description.

9. Recover the signing scalar. The TLV gives L = 12, so each nonce is below 2^244, in
   other words its top 12 bits are zero. For each signature, `s * k = z + r * d mod n`,
   so `k = a * d + b` with `a = r * s^-1` and `b = z * s^-1`. That is a hidden number
   problem with 48 samples. Normalise on the first signature, build the lattice of
   multiples of n with the ratios in the first row, run LLL, then take the closest
   vector to `-b`; the residual vector is the nonce vector. The recorded run is exact:
   `cvp_exact_match=True`, all 48 nonces below 2^244 with bit lengths 237 to 244, and
   `d = 278c1c0ea08921ba895d3d4c971e4e0a8c8b29d8016f42d9861fe49c6fa826c6`. The public
   key from that scalar matches Q (sha256
   `3ca892039e778a13b6200b7f4fc21dd16bcc8b65b0ba55a7b18674de02ba98e2`) and all 48
   signatures verify.

10. Unseal the type 0B record with section 3 of the datasheet. The KDF hashes the 32 byte
    scalar into a 32 byte key (sha256
    `3845973e3b9d2c9a0851a8354e8b9d2fe9aaddb9a8038357b14721c21e849e3e`), which loads
    as four little endian u64 words. The stream cipher steps a counter by
    `0x9E3779B97F4A7C15`, applies four rounds of add, rotate and xor per block, and
    emits `a ^ c` as eight little endian bytes. Five blocks cover the 33 byte blob, and
    XOR against the blob gives 33 printable bytes:

    ```
    68694354467b68316464336e5f6e756d6233725f6c3474746963655f6c65346b7d
    ```

11. Sanity check the recovered plaintext against the challenge shape. It starts and ends
    with the expected braces and has no padding, so the unsealing is complete rather
    than partially correct.

## Why it works

Two mistakes carry the challenge. The carrier is extremely sparse by design: a mean
step of 2048 samples between bits, and only the low byte of each sample touched, leaves
the audio statistics, the RIFF metadata and every sample level tool unchanged. Nothing
marks the channel except the pointer that the author left in the spectrogram.

The second mistake is in the payload. ECDSA nonces generated with twelve leading zero
bits leak the private key once enough signatures are available. Forty eight signatures
with 244 bit nonces give a lattice problem that solves exactly, so the sealed blob opens
without any brute force. The decoy strings exist to reward the wrong instinct, and the
`SM64` label in the panel points at a generator family that is not the one the sheet
specifies.

## Flag

```
hiCTF{h1dd3n_numb3r_l4ttice_le4k}
```

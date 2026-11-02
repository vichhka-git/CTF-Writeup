# Broken Signals

Forensics, 53 points, 763 solves. The handout is one file that no viewer will open. The
description says the file itself is wrong and asks for a repair. The damage is confined
to the first eight bytes, and restoring them turns the artifact back into a normal PNG
that carries the flag as rendered text.

## What you are given

`broken-signals.zip` expands to a single file, `broken_signal.dat`, 15,916 bytes. There
is no live service and no login material.

The local team notes match the distributed archive byte for byte, so the file has not
been altered during the event.

## Reproduction

1. Look at the first bytes and compare them with the PNG signature.

   ```sh
   xxd -l 16 broken_signal.dat
   # 00000000: 0000 0000 0d0a 1a0a ...
   ```

   A PNG must start `89 50 4e 47 0d 0a 1a 0a`. Here bytes 0 to 3 are zeroed and bytes
   4 to 7 are intact. That tells you the container is PNG and that only the magic was
   touched. `file` reports "data", and every chunk parser rejects the file, which is
   consistent with a broken signature rather than a broken body.

2. Confirm the rest of the container survived. Walk the chunk list: read a 4-byte
   length, a 4-byte type, the data, then a 4-byte CRC, and check the CRC over
   `type + data`.

   ```python
   import struct, zlib
   d = open('broken_signal.dat','rb').read()
   off = 8
   while off < len(d):
       ln = struct.unpack('>I', d[off:off+4])[0]
       typ = d[off+4:off+8]
       body = d[off+8:off+8+ln]
       crc = struct.unpack('>I', d[off+8+ln:off+12+ln])[0]
       print(hex(off), typ, ln, crc == zlib.crc32(typ + body))
       off += 12 + ln
   ```

   The recorded chunk offsets are IHDR at `0x8`, cHRM at `0x21`, bKGD at `0x4d`, tIME
   at `0x5f`, tEXt at `0x72`, `0xa3` and `0xd4`, IDAT at `0x108`, IEND at `0x3e20`, and
   every row printed by the loop is True. For example the IHDR CRC over `IHDR` plus its
   13 payload bytes is `bd273981`, which equals the stored value. A damaged header would
   have failed here.

3. Read the IHDR payload to learn the geometry. Width is 400, height is 300, bit depth
   is 16, colour type is 6 (RGBA), and the interlace flag is 0.

4. Sanity check the image data, so you know the dimensions are real and the file is not
   truncated. The IDAT stream starts at `0x110`, is 15,628 bytes long, and begins with
   `78da`. Inflating it gives exactly 960,300 bytes, which is 300 rows of one filter
   byte plus `400 * 4 * 2` bytes. The recorded filter distribution is 275 rows of filter
   2, 20 rows of filter 4 and 5 rows of filter 1.

5. Repair the signature by rewriting the first four bytes.

   ```python
   d = open('broken_signal.dat','rb').read()
   open('fixed.png','wb').write(bytes.fromhex('89504e47') + d[4:])
   ```

   `file fixed.png` now reports a 400 x 300 16-bit RGBA PNG.

6. Convert to 8-bit RGB and look at it. The image is a dark slate panel with a white
   headline reading "SIGNAL INTERCEPTED" and a red line near the bottom holding the
   flag. The local notes record the message text but not pixel coordinates or an OCR
   pass, so read it from the rendered image.

7. Check the obvious alternative carriers before stopping. The recorded results are
   negative for all of them: IEND ends exactly at the end of the file (`0x3e20` to
   `0x3e2b`) with no appended data, there are no unknown chunks, and the three tEXt
   chunks contain only ImageMagick timestamps with a date of 2026-10-15.

## Why it works

PNG readers trust the eight-byte signature before they trust anything else. Zeroing the
first four bytes makes every parser classify the file as unknown and bail out before it
ever reaches the IHDR chunk, even though the chunk stream is complete and CRC-valid. The
challenge is a header repair, and the only thing you need to recognise is the intact
`0d 0a 1a 0a` tail of the signature.

## Flag

```
hiCTF{h34d3r_r3p41r_m4st3r}
```

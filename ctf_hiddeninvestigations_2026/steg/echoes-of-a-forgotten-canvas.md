# Echoes of a Forgotten Canvas

Steganography, 59 points, 314 solves. One PNG, and it is not the size it claims to be.
The compressed pixel stream is 500 rows longer than the header says, and the extra rows
carry a drawn string in the alpha channel. An archive appended after IEND continues the
chain. The accepted flag is longer than the drawn string, so the canvas is a partial
reveal rather than the answer.

## What you are given

`echoes-of-a-forgotten-canvas.zip` expands to a single file, `chall.png`, 8,877,501
bytes. There is no live service and no login material.

## Reproduction

1. Walk the PNG chunk list. The file has IHDR, cHRM, pHYs, bKGD, a zTXt block holding a
   Photoshop XMP profile, an iTXt block with `XML:com.adobe.xmp`, 85 IDAT chunks and
   IEND, which ends at offset 0x543446 (5,518,406). IHDR says 4000 by 4000, 8-bit RGBA,
   non-interlaced, and every chunk CRC verifies except IHDR.

2. Inflate the IDAT stream and compare it with the declared geometry. It produces
   72,004,500 bytes, and one row of a 4000 pixel RGBA image is `1 + 4000 * 4 = 16001`
   bytes, so 72,004,500 / 16001 = 4500 rows. The image is 500 rows taller than its own
   header.

3. Prove the height instead of guessing it. 4500 is `0x00001194`. Write those four bytes
   over the IHDR height field at offsets 20 to 23 and recompute the CRC over the IHDR
   type plus payload:

   ```sh
   python3 -c 'import zlib;b=bytearray(open("chall.png","rb").read());b[20:24]=(4500).to_bytes(4,"big");print(hex(zlib.crc32(b[12:29])),b[29:33].hex())'
   # 0x4675412a 4675412a
   ```

   The recomputed CRC equals the stored value `4675412a`, so 4500 is the real height and
   the header was corrupted on purpose. The repaired canvas is 4000 by 4500.

4. Read the restored rows through the alpha channel. Ink exists only in rows 4461 to
   4482 and columns 3758 to 3971; RGB is 0 in every inked pixel, so the glyphs are pure
   coverage. Rows 4000 to 4460 and 4483 to 4499 are empty and there is no ink to the
   right of column 3971. Composite on white or render alpha at 6x to 8x and the band
   reads 19 glyphs:

   ```
   hiCTF{mu1t!14y3r3d_
   ```

   The last glyph is 13 pixels wide with ink only in rows 4480 to 4482, which is a
   baseline bar, so it is an underscore. No closing brace is drawn.

5. Follow the appended archive. Immediately after IEND there is a 3,359,095 byte ZIP
   starting `50 4b 03 04`. It holds one entry, `carrier.jpg`, uncompressed size
   3,364,164, compressed 3,358,907, general purpose flag 9 (encrypted, with a data
   descriptor), method 8, CRC `0x4230eebb`. The drawn string is not the password. The
   password is `dreamcatcher`, a plain rockyou entry found by a dictionary run, and it
   verifies against both the CRC and the size:

   ```sh
   tail -c +5518407 chall.png > carrier.zip
   unzip -P dreamcatcher carrier.zip carrier.jpg
   ```

6. Inspect `carrier.jpg`. It is 2816 by 1536, baseline JPEG, every quantization table
   flat at quality 100, no EXIF, and EOI is the last byte pair. The content is a photo of
   a handwritten poem on a sheet of paper, titled WILDER ECHOES, fourteen lines long.
   The acrostics were checked and are gibberish, so the poem is not a ciphertext. It is
   a word list, and the word `profound` appears twice in it.

7. Run steghide on the carrier with that word. It reports the embedded name `finall.jpg`
   and writes 113,614 bytes, a 495 by 647 alley photograph with an "APARTMENTS GAJETA"
   awning. This is where the recorded chain stops.

8. Check the last image before believing it is another layer. The local record is
   negative for all of these: single SOI/EOI pair with no trailing bytes, EXIF holding
   only Orientation, no `hiCTF` string, pixel LSB bit planes random, DCT coefficient LSB
   random, no zlib, gzip, bzip2, xz, ZIP or JPEG stream carved at any offset, and
   stegseek finds no passphrase with rockyou or with a 337 word list built from the poem.

9. Compare what was drawn with what was accepted. The band is exactly the first 19
   characters of the accepted flag, so the canvas is a deliberate prefix. The local notes
   do not record where the remaining characters, `_st3g0o_ju5t_l0v333}`, were recovered;
   the only local record of the full string is the accepted entry in the team submission
   log. Two earlier submissions, `hiCTF{mu1t!14y3r3d_}` and `hiCTF{mu1t!14y3r3d}`, were
   rejected, which is consistent with the band being incomplete rather than misread.

## Why it works

The PNG is internally inconsistent in a way that proves its own repair: the IDAT stream
length and the stored IHDR CRC both say 4500 rows while the header says 4000. Tools that
trust the header simply crop the payload away, and viewers that composite RGBA against a
page background do not show alpha-only pixels at all, so the band is invisible both ways.

The rest of the chain is a password ladder where each rung is hinted by the previous
artifact: a rockyou word opens the appended archive, and a word printed on the carrier
opens the next image. The weakness is that both secrets are recoverable from local
material alone, one from a wordlist and one from reading the carrier's own content. The
local notes document the ladder to `finall.jpg` but not the last step that produced the
full accepted flag.

## Flag

```
hiCTF{mu1t!14y3r3d_st3g0o_ju5t_l0v333}
```

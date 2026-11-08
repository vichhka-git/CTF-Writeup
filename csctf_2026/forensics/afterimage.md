# Afterimage

**Category:** Forensics · **Points:** 450 · **Flag:** `CSCTF{6f86acdd1d10e0d8a5a541bb}`

## What the handout gives you

The handout provides a single image file capturing a terminal screen that was cropped before being shared.

- `relay-capture.png` — 26,174 bytes, PNG image data, 520x340 pixels, 8-bit RGB (color type 2).

## Walkthrough

1. **Inspect PNG chunk structure.** A standard PNG file ends with an `IEND` chunk of 12 bytes (`00 00 00 00 49 45 4e 44 ae 42 60 82`). Parsing chunks sequentially from the 8-byte PNG signature shows the cropped image's `IEND` chunk ends at byte offset 14,263. The file contains 11,911 additional bytes after `IEND`.

```bash
python3 -c "data=open('relay-capture.png','rb').read(); print('Trailer bytes:', len(data[14263:]))"
```

2. **Diagnose the crop artifact.** The trailing bytes indicate an Acropalypse truncation failure (CVE-2023-21036 / CVE-2023-28310). When the editor saved the cropped screenshot, it wrote the new file data starting at offset 0 without truncating the existing file on disk. The bytes past offset 14,263 belong to the original, uncropped file.

3. **Locate trailing image data.** Scanning the trailing data locates complete `IDAT` chunks starting at byte offset 14,537. Each chunk has a length field of 1,024 bytes. The original file concluded at offset 26,162 with its own `IEND` chunk. The bytes between offset 14,263 and 14,537 contain the end of chunk 13 from the original image, minus 16 bytes overwritten by the new `IEND` chunk.

4. **Reconstruct the DEFLATE bitstream.** DEFLATE streams pack symbols bit-by-bit from least-significant to most-significant bit. Because the start of the original stream was overwritten, the remaining compressed data starts at an unknown bit offset. Extract the payload bytes from all trailing `IDAT` chunks, strip chunk headers and CRCs, and construct 8 bit-shifted candidate bytestreams.

5. **Search for viable DEFLATE blocks.** Prepend each candidate stream with an uncompressed block of 32,768 dummy bytes (`0x8000`) so back-references do not abort decompression. Test each bit offset using a raw DEFLATE decompressor with `wbits=-15`. At bit offset 24,984, the decompressor finds a valid dynamic Huffman block that consumes the remainder of the file with zero unused trailing bytes.

6. **Calculate image geometry.** Decompressing from bit offset 24,984 outputs exactly 312,200 bytes. With an image width of 520 pixels and 3 bytes per pixel (RGB), each scanline requires 1 filter byte plus 1,560 pixel bytes, totaling 1,561 bytes per row. Dividing 312,200 by 1,561 yields exactly 200 uncropped scanlines.

7. **Render the recovered pixels.** Pack the 312,200 bytes into a new 520x200 PNG file. Any filter byte replaced by back-references to the dummy prefix is reset to 0. Opening the generated image displays the cropped bottom of the terminal window.

## Answer

The recovered scanlines display the station recovery key banner and custody details:

`CSCTF{6f86acdd1d10e0d8a5a541bb}`

## Notes

The cropped image has height 340, while the recovered tail has height 200, giving an original canvas height of 540 pixels. Attempting to decompress without the 32KB sliding window prefix fails immediately because LZ77 match distances reference data from the earlier rows.

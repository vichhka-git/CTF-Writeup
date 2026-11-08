# Operation Dawn: The Reconnaissance Plate

**Category:** Misc · **Points:** 120 · **Flag:** `CSCTF{11_the_guns_behind_the_ridge_3f8c21}`

## What the handout gives you

The handout contains a single image artifact representing an encoded military observation plate from the Operation Dawn theatre.

- `recon-plate.png` — a 256x256 pixel PNG image with 8-bit RGB color channels, measuring 110 KB on disk. The image depicts aerial reconnaissance terrain data.

## Walkthrough

1. **Perform bitplane analysis.** Inspecting the image pixels with standard steganography analysis tools reveals anomalies localized to the top scanlines. Scanning the file with `zsteg recon-plate.png` reports detected data streams in the first few rows. Pixel analysis confirms that across rows 4 through 255, the two lowest significant bits of every color channel are uniformly cleared to zero. Only the first four pixel rows (`y = 0, 1, 2, 3`) carry non-zero data in bit 0 and bit 1.

2. **Calculate bitplane capacity.** With 4 scanline rows, 256 horizontal columns, and 3 color channels (Red, Green, Blue), the header region provides:
   `4 * 256 * 3 = 3072 bits = 384 bytes`
   This capacity stores two distinct, parallel bit streams embedded within the image:
   - Plane 0: constructed from bit 0 (`channel & 1`) of each sample.
   - Plane 1: constructed from bit 1 (`(channel >> 1) & 1`) of each sample.

3. **Examine stream framing.** Extracting the bits sequentially in row-major order (`y` from 0 to 3, `x` from 0 to 255, and color channels in Red, Green, Blue sequence) and packing them MSB-first into bytes reveals structured framing at the head of each stream:
   - A 4-byte big-endian unsigned integer specifies the compressed payload length.
   - The payload immediately follows, starting with the standard two-byte gzip magic header `0x1f 0x8b`.
   - Plane 0 encodes a length header of 268 bytes (`0x0000010c`).
   - Plane 1 encodes a length header of 276 bytes (`0x00000114`).

4. **Decompress embedded archives.** Slicing the exact byte count indicated by each header and decompressing the gzip data with `zlib` produces two POSIX ustar archive blocks:
   - **Bitplane 0:** Unpacks a single text file named `drill-order.txt`. The contents state: `"DRILL SERIAL 11 HOLD THE RIDGE LINE UNTIL RELIEVED CODE 48B473"`. This record corresponds to a simulated garrison training exercise.
   - **Bitplane 1:** Unpacks an authentic field dispatch file named `recon-report.txt`. The contents state: `"RECON SERIAL 11 THE GUNS BEHIND THE RIDGE CODE 3F8C21"`.

5. **Differentiate the decoy drill from field intelligence.** The challenge briefing specifies authentic reconnaissance reporting rather than training exercises. The drill message embedded in bitplane 0 acts as a decoy targeted at automated LSB extraction utilities that only inspect the single lowest significant bit (bit 0). Bitplane 1 preserves the true tactical observation.

6. **Format the flag.** The Operation Dawn series structures flags according to a deterministic schema: `CSCTF{<serial>_<normalized_text>_<code>}` in lower case with underscores replacing whitespace. Extracting serial number 11, report body `"the guns behind the ridge"`, and confirmation code `"3f8c21"` constructs the flag token:
   `CSCTF{11_the_guns_behind_the_ridge_3f8c21}`.

## Answer

Extract the authenticated reconnaissance observation record from bitplane 1 to recover the flag:

`CSCTF{11_the_guns_behind_the_ridge_3f8c21}`

## Notes

Naive LSB extractors dump bit 0 by default, exposing the drill decoy plate. Bit 1 must be parsed independently using MSB-first byte packing across RGB scanlines 0 through 3. Both payloads use a 4-byte big-endian prefix before the gzip stream.
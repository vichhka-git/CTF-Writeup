# Flotsam

**Category:** forensics · **Points:** 200 · **Flag:** `CSCTF{flotsam_0e91019a8e70267f550895930247d088}`

## What the handout gives you

A raw flash memory dump from the voyage data recorder of the MV Ortelia, read chip-off without filesystem metadata.

- `recorder-sectors.img` — 35,840-byte disk image consisting of 70 sectors of 512 bytes each.

The task is to carve the vessel's last navigational chart frame (a PNG image) from the fragmented sectors and read the recovery key printed across it.

## Walkthrough

### 1. Classify the disk sectors

Inspect the image in 512-byte blocks. Scanning magic numbers and text strings across all 70 sectors reveals four content types:

- Sectors 0–2: ASCII NMEA GPS sentences (`$GPRMC`).
- Sectors 3–20: 18 sectors of high-entropy compressed data.
- Sector 21: 512 null bytes.
- Sectors 22–33: 12 sectors containing a JPEG image (`\xFF\xD8\xFF\xE0` JFIF header at sector 22).
- Sector 34: 512 null bytes.
- Sectors 35–41: 7 sectors of high-entropy compressed data.
- Sectors 42–43: 1,024 null bytes.
- Sectors 44–47: 4 sectors of compressed data, ending with an `IEND` chunk.
- Sectors 48–51: 4 sectors of ASCII NMEA GPS sentences.
- Sectors 52–67: 16 sectors starting with a PNG file signature (`\x89PNG\r\n\x1a\n`).
- Sectors 68–69: 1,024 null bytes.

### 2. Parse the PNG chunk headers

Inspect sector 52, which contains the start of the PNG file:

- Offset 0: 8-byte PNG signature `89 50 4E 47 0D 0A 1A 0A`.
- Offset 8: `IHDR` chunk defining dimensions 760×520, 8-bit depth, and RGB color (`00 00 02 F8 00 00 02 08 08 02`).
- Offset 33: `IDAT` chunk header declaring a compressed payload length of 22,630 bytes (`0x00005866`).

Compute the complete file size required to satisfy the chunk structure:
8 (signature) + 25 (`IHDR`) + 12 (`IDAT` header and CRC) + 22,630 (`IDAT` payload) + 12 (`IEND`) = 22,687 bytes.

At 512 bytes per sector, 22,687 bytes spans 45 sectors: 44 full sectors of 512 bytes (22,528 bytes) plus a final sector holding 159 bytes (`22687 - 22528 = 159`).

### 3. Verify the file terminator

Inspect sector 47. At offset 147 sits the 12-byte `IEND` chunk:

`00 00 00 00 49 45 4E 44 AE 42 60 82`

The chunk ends at offset 159 of sector 47, matching the exact 159-byte remainder calculated from the `IDAT` header. Everything after offset 159 in sector 47 is padding null bytes.

### 4. Reconstruct the fragmented stream

The non-null, non-JPEG, non-NMEA data sectors form four contiguous runs:

- Run D: sectors 52–67 (16 sectors, containing `IHDR` and the start of `IDAT`)
- Run A: sectors 3–20 (18 sectors)
- Run B: sectors 35–41 (7 sectors)
- Run C: sectors 44–47 (4 sectors, ending at byte 159 of sector 47)

Summing sector counts gives `16 + 18 + 7 + 4 = 45` sectors. Because Run D contains the file header and Run C contains the `IEND` chunk, the logical order is:

`Run D (52..67) + Run A (3..20) + Run B (35..41) + Run C (44..47, first 159 bytes)`

Concatenating the sectors in this sequence yields a 22,687-byte file. The deflated `IDAT` stream inflates cleanly without CRC errors, expanding to 1,186,120 uncompressed bytes (`(760 * 3 + 1) * 520`).

## Answer

Open the reassembled PNG in an image viewer:

`open recovered.png`

The image displays an electronic chart frame for the MV Ortelia marked "frame 0x1A4" with coordinates for the vessel's last fix. The center overlay displays the recovery key:

`CSCTF{flotsam_0e91019a8e70267f550895930247d088}`

## Notes

Sectors 22 through 33 contain a valid JPEG image showing a generic map background. Carving that file out yields an image with no text overlay; it is an older decoy asset remaining in unallocated flash blocks.

The NMEA blocks in sectors 0–2 and 48–51 contain regular `$GPRMC` sentences recording timestamp `060000.00` and vessel speeds, but no flag strings.

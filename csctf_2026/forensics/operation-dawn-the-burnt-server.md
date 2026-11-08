# Operation Dawn: The Burnt Server

**Category:** Forensics · **Points:** 120 · **Flag:** `CSCTF{04_flint_arc_eastward_relay_6aa299}`

## What the handout gives you

The handout provides a tar archive containing salvaged images and metadata from a damaged server rack:

- `server-remains.tar` (4,198,400 bytes, SHA-256 `98fd39f5957606e08b2a77dd253d6627366fd5853ecbd8f0f3ff81cc500345af`) — archive holding:
  - `SALVAGE.txt` (434 bytes) — field notes documenting a 3-drive hot-swap bay where slot 1 burned out.
  - `disk0.img` (2,097,152 bytes) — raw dump of the intact disk from slot 0.
  - `disk2.img` (2,097,152 bytes) — raw dump of the intact disk from slot 2.

## Walkthrough

1. **Read the salvage log and establish array parity.** The text note confirms that the storage system originally contained three identical drives, with drive slot 1 completely destroyed. In a three-disk fault-tolerant RAID-5 array, data blocks and parity blocks are distributed across all three disks such that `disk0 ^ disk1 ^ disk2 = 0`. Because XOR is self-inverting, the missing disk is restored by XORing the two surviving drives: `disk1 = disk0 ^ disk2`.

```sh
tar -xf server-remains.tar
```

2. **Reconstruct the missing disk image.** Computing the byte-for-byte XOR between `disk0.img` and `disk2.img` produces a 2 MB `disk1.img`. Inspecting the first sector of `disk1.img` reveals standard FAT16 boot sector structures: the OEM name `mkfs.fat` at byte offset 3 and the boot signature `0x55AA` at offset 510.

3. **Parse the FAT16 parameters.** Examining the BIOS Parameter Block located at sector 0 of `disk1.img` provides the geometry of the underlying filesystem:
   - Sector size: 512 bytes
   - Sectors per cluster: 1
   - Reserved sectors: 1
   - FAT tables: 2
   - Sectors per FAT: 32
   - Root directory capacity: 512 entries (occupying 32 sectors)

   The data region begins immediately after the reserved sector, both FAT tables, and the root directory area: `1 + (2 \times 32) + 32 = 97` sectors. Because cluster numbering starts at cluster 2, a cluster index `C` begins at physical sector `97 + (C - 2)`.

4. **Locate the register entry in the root directory.** Parsing the root directory table located at sectors 65 through 96 exposes an entry for `TRAIN.GZ`. The metadata records:
   - Starting cluster: 16 (which maps to sector `97 + (16 - 2) = 111`)
   - File length: 16,599 bytes

5. **Trace the RAID-5 stripe boundary.** The target archive requires 33 sectors (`16,599 / 512 = 32.42`). The RAID array uses a 64 KB (128 sectors) stripe size. On `disk1.img`, Chunk 0 covers sectors 0 through 127. Starting at sector 111 leaves 17 sectors (sectors 111 through 127, totaling 8,704 bytes) before the stripe ends.
   The remaining 16 sectors (7,895 bytes) spill over into Chunk 1. Under left-symmetric RAID-5 striping across three drives, Chunk 1 begins at sector 0 of `disk2.img`.

6. **Reassemble the gzip stream.** Slicing sectors 111 through 127 from `disk1.img` and concatenating them with sectors 0 through 15 from `disk2.img` yields the complete 16,599-byte gzip stream. The output begins with the standard gzip header `1f 8b 08 00`. Decompressing this stream recovers the full text of the medical transport movement register.

## Answer

Decompressing the assembled archive produces the train movement register. Grepping the output for the flag token gives:

`CSCTF{04_flint_arc_eastward_relay_6aa299}`

## Notes

Extracting only from `disk1.img` produces an incomplete gzip stream that terminates abruptly with `unexpected end of file`. Reconstructing the stripe transition across the 64 KB boundary onto `disk2.img` is required to complete decompression.

# Night Clerk

**Category:** Forensics · **Points:** 120 · **Flag:** `CSCTF{hid_skew_redline}`

## What the handout gives you

The handout contains an uncompressed raw disk image extracted from a depot terminal:

- `terminal.dd` (8,388,608 bytes, SHA-256 `fb76b12579f7c1314df6e7556548a61c73c96157d95e77ba253c371c9d78bfb7`) — raw image of an NTFS-formatted removable storage drive.

## Walkthrough

1. **Identify the file system structure.** Run `fsstat terminal.dd` to examine the partition layout. The image contains a standard NTFS file system with 512-byte sectors and 4,096-byte allocation clusters. The volume label indicates a routine administrative workstation used for depot personnel records.

2. **Recover allocated and deleted files.** Extract all directory entries and unallocated fragments using Sleuth Kit recovery tools:
   ```bash
   tsk_recover -e terminal.dd recovered/
   ```
   The command recovers three files from the root directory: `audit-0214.log` (384 bytes), `README.TXT` (59 bytes), and `night_audit.docx` (2,578 bytes). Inspecting the file metadata shows that `night_audit.docx` had its directory entry unlinked shortly before terminal shutdown.

3. **Triage the recovered exhibits.** `audit-0214.log` contains ordinary depot dispatch entries recording truck movements. `README.TXT` contains administrative notes regarding standard shift changes. `night_audit.docx` is a Microsoft Word OpenXML archive that corresponds to the incident timeframe.

4. **Decompress the document archive.** Unpack the document container to expose its internal XML markup:
   ```bash
   unzip -q recovered/night_audit.docx -d docx_payload/
   ```
   The extraction yields standard OpenXML structure, including `word/document.xml`, `word/styles.xml`, and relationship metadata.

5. **Inspect the document text and revision markup.** Open `docx_payload/word/document.xml` in a text editor. While normal paragraph runs (`<w:t>`) show mundane logistics status notes, a tracked insertion block (`<w:ins>`) contains an unusual hexadecimal payload:
   `7a6a7a6d7f4251505d664a525c4e664b5c5d5550575c44`

6. **Determine the obfuscation scheme.** Convert the 46 hexadecimal characters into 23 raw bytes. Because competition flags use the standard prefix `CSCTF{`, test for a single-byte XOR cipher. The first byte of the ciphertext is `0x7a`, and ASCII `'C'` is `0x43`. Calculating `0x7a ^ 0x43` yields key candidate `0x39`. Testing the next bytes confirms the match:
   - `0x6a ^ 0x39 = 0x53` (`'S'`)
   - `0x7a ^ 0x39 = 0x43` (`'C'`)
   - `0x6d ^ 0x39 = 0x54` (`'T'`)
   - `0x7f ^ 0x39 = 0x46` (`'F'`)
   - `0x42 ^ 0x39 = 0x7b` (`'{'`)

7. **Decode the full string.** Applying the single-byte XOR key `0x39` across the entire 23-byte sequence translates every byte into valid printable ASCII characters, culminating in `0x44 ^ 0x39 = 0x7d` (`'}'`).

## Answer

Deciphering the hex stream with XOR key `0x39` yields the plaintext flag:

`CSCTF{hid_skew_redline}`

## Notes

Opening `night_audit.docx` in graphical office software typically hides deleted or unapproved revision marks depending on default display settings. Direct inspection of `word/document.xml` guarantees visibility of all tracked `<w:ins>` and `<w:del>` nodes regardless of presentation toggles.

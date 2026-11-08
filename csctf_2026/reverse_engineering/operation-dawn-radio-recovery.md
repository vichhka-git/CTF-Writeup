# Operation Dawn: Radio Recovery

**Category:** Reverse engineering · **Points:** 120 · **Flag:** `CSCTF{05_train_kestrel_d48e1f}`

## What the handout gives you

The README describes `firmware.bin` as a constructed recovery bundle, not a bootable radio image. Its size is 1,048,576 bytes and its SHA-256 is `ae253e80cfca3035fe1e882c3c26a75b1d701f1b1bb343ba290d590573bc4313`.

- `firmware.bin` is a custom `DWFW` container with four named partitions.
- `README.md` gives the file size, digest, and the recovery-token objective.

## Walkthrough

1. Read the first eight bytes: `DWFW`, version 1, and partition count 4. The table starts at offset 8. Each 20-byte entry holds an 8-byte name followed by little-endian offset, size, and CRC32 fields. The four entries are:

   - `loader`: offset `0x200`, size 111, CRC32 `e08559b1`.
   - `ubootenv`: offset `0x270`, size 16,384, CRC32 `0e0748da`.
   - `msgcat`: offset `0x4270`, size 258, CRC32 `5a21c5b2`.
   - `rootfs`: offset `0x4380`, size 633, CRC32 `65047329`.

   Each stored CRC32 matches its partition. This confirms the offsets and sizes before interpreting the contents.

2. The rootfs begins with zlib bytes `78 f9 55 d4 5a 6c`. The FDICT bit is set, and `0x55d45a6c` is the dictionary Adler-32. The `msgcat` partition has that Adler-32, so it is the preset dictionary needed to decompress rootfs. The output is a 2,560-byte CPIO `newc` archive, identified by magic `070701`. Its entries store name and data lengths as hexadecimal text and align each name and payload to four bytes.

3. The archive contains `etc/config/radio` and `etc/init.d/S40admin`. The radio config stores `admin_token=7f71b81e5beb0c17a43e6ff1554ca42178e348509e2642f4081a9e7b7bed`. The init script reads `ethaddr`, removes its colons, and XORs each token byte with the corresponding MAC byte. Its index wraps every six bytes, so the selected U-Boot MAC controls the recovered token. Decode the hex token into bytes before applying XOR; XORing its ASCII hex characters produces a different result. The script prints the recovered byte string as the admin key.

4. The `ubootenv` partition holds two 8 KiB redundant environments. Each begins with a stored CRC32, then a one-byte flag, followed by NUL-delimited variables; the CRC checks the data after the flag. The first copy has flag 6 and MAC `00:11:22:33:44:55`; the second has flag 7 and MAC `3c:22:fb:4a:1d:90`. The higher flag marks the active copy. XOR the token bytes with `3c 22 fb 4a 1d 90` repeatedly to recover the admin key.

## Answer

The decrypted admin key is the requested flag: `CSCTF{05_train_kestrel_d48e1f}`.

## Notes

The rootfs stream cannot be decompressed without its preset dictionary. The old flag-6 environment is valid but superseded by the flag-7 copy, so using its MAC produces the wrong token.

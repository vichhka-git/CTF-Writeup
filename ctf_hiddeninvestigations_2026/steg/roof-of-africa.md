# Roof of Africa

Steganography, 53 points, 692 solves. A photograph of Kilimanjaro with a steghide payload
keyed by the mountain's best known number. The file is clean at every container level, so
the only channel left is the JPEG's DCT coefficients.

## What you are given

`roof-of-africa.zip` expands to a single file, `roof_of_africa.jpg`, 624,567 bytes, a
1600 by 1056 baseline JFIF image. There is no live service and no login material.

## Reproduction

1. Walk the JPEG markers and confirm there is nothing appended. The file starts
   `ffd8ffe000104a46494600`, APP0 is at 0x2 with length 16, the two DQT segments are at
   0x14 and 0x59 with length 67, SOF0 is at 0x9e with length 17, four DHT segments sit at
   0xb1, 0xd2, 0x189 and 0x1aa, and SOS is at 0x261 with length 12. The entropy coded
   scan starts at 0x26f and the EOI marker `ffd9` at 0x987b5 is the final two bytes of
   the file, so there is no trailing archive and no second image.

   ```sh
   python3 -c 'from pathlib import Path;d=Path("roof_of_africa.jpg").read_bytes();print(len(d), d.rfind(bytes.fromhex("ffd9"))+2)'
   # 624567 624567
   ```

2. Rule out the easy carriers. There is no EXIF, no ICC profile and no COM segment, so
   metadata is empty. Decoding the pixels and scanning bit planes 0 through 7 on all
   three channels finds no flag text, so pixel LSBs are not the channel either. The SOF0
   payload `08 0420 0640 03 011100 021101 031101` shows 1x1 sampling on all three
   components, so there is no chroma subsampling artefact to mine.

3. Decode the hint. The description says Africa's highest peak, and "the mountain's most
   famous number". The peak is Kilimanjaro and the famous number is its height, 5895
   metres. That number is the passphrase, not a password to be found somewhere in the
   file.

4. Ask steghide what is inside before extracting. The information-only parse with the
   passphrase reports the embedded structure:

   ```sh
   steghide info roof_of_africa.jpg -p 5895
   # embedded file "roof_flag_v2.txt":
   #   size: 38.0 Byte
   #   encrypted: rijndael-128, cbc
   #   compressed: yes
   ```

   The same output gives the cover capacity as 31.4 KB. A wrong passphrase either fails
   to decrypt the header or reports nothing, so this output is already a confirmation
   that 5895 is correct.

5. Extract and read the payload.

   ```sh
   steghide extract -sf roof_of_africa.jpg -p 5895 -xf out_5895.bin -f
   xxd out_5895.bin | head -4
   ```

   The file is 38 bytes: 37 characters of flag plus a newline, no padding and no
   wrapper. The first bytes are `68 69 43 54 46 7b`, which is `hiCTF{`.

6. Note the passphrase candidates that were recorded as rejected, so a reproduction does
   not waste time on them: `19341` (the height in feet), `kilimanjaro`, `Kilimanjaro`,
   `KILIMANJARO` and `5895m`. The metres value without a unit suffix is the one that
   works.

7. Keep the original JPEG as the extraction input. Decoding and re-encoding, even at high
   quality, requantises the coefficients and destroys the payload. If a visual check is
   wanted, write the decoded copy to a different file and leave the original untouched.

## Why it works

steghide does not touch headers, comment fields or appended bytes. It selects pseudo
random DCT coefficients from a passphrase derived sequence and adjusts their least
significant bits, which is why every container check comes back clean and why the payload
has no byte aligned magic to carve. The only way in is to supply the right passphrase to
a coefficient aware tool.

The design weakness is the passphrase itself. It is fully determined by two facts in the
description, the name of the peak and its height, and the height in metres is the first
number any search returns. Once that number is tried, the payload is a plain file with no
further encryption layer of its own.

## Flag

```
hiCTF{h4kun4_m4t4t4_m34ns_n0_w0rr13s}
```

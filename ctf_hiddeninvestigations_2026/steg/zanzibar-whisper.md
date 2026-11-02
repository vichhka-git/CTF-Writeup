# Zanzibar Whisper

Steganography, 53 points, 668 solves. A photograph from the Zanzibar shore carrying a
steghide payload under an empty passphrase. The container is clean, so the payload is in
the JPEG's DCT coefficients, and the access control is nominal.

## What you are given

`zanzibar-whisper.zip` expands to a single file, `zanzibar_whisper.jpg`, 151,647 bytes, a
1024 by 683 baseline JFIF image. There is no live service and no login material.

## Reproduction

1. Map the JPEG markers and confirm the file ends at its own data. The file starts
   `ffd8ffe000104a46494600`. APP0 is at 0x2 with length 16, the two DQT segments are at
   0x14 and 0x59 with length 67, SOF0 is at 0x9e with length 17, four DHT segments sit at
   0xb1, 0xd2, 0x189 and 0x1aa, and SOS is at 0x261 with length 12. The entropy coded scan
   runs from 0x26f and EOI `ffd9` at 0x2505d is the last two bytes.

   ```sh
   python3 -c 'from pathlib import Path;d=Path("zanzibar_whisper.jpg").read_bytes();print(len(d), d.rfind(bytes.fromhex("ffd9"))+2)'
   # 151647 151647
   ```

   Whole file entropy is 7.766 bits per byte and the scan entropy is essentially the same,
   which is what an ordinary compressed photograph looks like. There is no EXIF, no COM
   segment, and no ZIP, PNG or RAR signature, so there is no appended archive to extract.

2. Check the SOF0 and SOS payloads while the markers are open. SOF0 is
   `08 02ab 0400 03 011100 021101 031101`, so all three components use 1x1 sampling, and
   SOS is `03010002110311003f00`, an ordinary sequential Huffman coded scan. Nothing here
   is malformed, so the geometry is not the trick.

3. Ask steghide what it sees, using an empty passphrase:

   ```sh
   steghide info zanzibar_whisper.jpg -p ''
   # embedded file "zanzibar_flag2.txt":
   #   size: 28.0 Byte
   #   encrypted: rijndael-128, cbc
   #   compressed: yes
   ```

   The information-only parse reports a real embedded structure, so the payload exists in
   the coefficient domain where there is no byte aligned signature to carve. The stated
   cover capacity is 6.4 KB, which is comfortable for a 28 byte file.

4. Extract it.

   ```sh
   steghide extract -sf zanzibar_whisper.jpg -p '' -xf out.bin -f
   xxd out.bin
   ```

   The file is 28 bytes: 27 characters of flag plus a newline. The first bytes are
   `68 69 43 54 46 7b`, which is `hiCTF{`, and the last content byte is `7d`, the closing
   brace.

5. Resist the temptation to carry over the sibling challenge's passphrase. The marker
   layout here is the same as `roof-of-africa.jpg`, which is a strong hint to reuse the
   coefficient tool, and a weak hint about the passphrase. Here the passphrase is the empty
   string, not a number or a word, so the right move is to test the empty passphrase first
   rather than crack anything.

6. Keep the original JPEG as the extraction input. Any decode and re-encode pass
   requantises the DCT coefficients and destroys the payload, so write any visual copy to a
   separate file.

## Why it works

steghide stores its payload in pseudo randomly selected DCT coefficients, keyed by the
passphrase, so the image's headers, comment slots and trailing bytes all stay untouched
and every container level check comes back clean. That is why the marker walk and the
appended data check are worth doing first: they close off the cheap channels and leave the
coefficient domain as the only candidate.

The weakness is the passphrase convention. An empty passphrase still runs the same
encryption path, so the payload reports as `rijndael-128, cbc` and looks protected, but
the key is derived from nothing. Anyone who tries the empty string before reaching for a
wordlist gets the file on the first attempt.

## Flag

```
hiCTF{sp1c3_1sl4nd_s3cr3ts}
```

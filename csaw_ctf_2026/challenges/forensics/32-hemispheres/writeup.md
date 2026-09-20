# CSAW CTF Quals 2026 - Hemispheres (Forensics, ID 32)

## Challenge Information
- **Name:** Hemispheres
- **Category:** Forensics
- **ID:** 32
- **Author:** WubberDuckkie
- **Flag:** `csaw{0n3_f1l3_tw0_truth5_p0lygl0t_m4g1c}`

## Description
> We received an image. Just an image. Our analyst swears there's more to it, but every tool says it's a perfectly ordinary PNG: it opens, it renders, it looks like a picture.
> 
> They're not wrong. But they're not seeing everything. And even when you find the second thing, it's locked. The key was never written down.

## Analysis & Solution

### 1. Initial Reconnaissance
Examining the provided file `files/the_signal.png` reveals:
- A valid PNG image (720 x 400, RGB).
- In the PNG metadata chunks, there is a `tEXt` comment:
  `Comment: Look past IEND for the lock. The key is in the pixels, not the words.`
- Examining the binary data past the `IEND` chunk reveals 326 bytes starting with `PK\x03\x04` — a password-protected ZIP archive containing `flag.txt` and `README.txt`.

### 2. Identifying the Key in the Pixels
The challenge description and comment emphasize:
- *"The key was never written down."*
- *"The key is in the pixels, not the words."*

The visible words in the image depict philosophical text and quote fragments. However, analyzing the pixel values across all color channels shows an anomaly in row 0:
- While all other background pixels have even RGB values (`[16, 18, 28]`), row 0 contains 100 pixels where the Blue channel value is `29` (`diff = [0, 0, 1]`), meaning the least significant bit (LSB) of the Blue channel is set to `1`.
- Extracting the Blue channel LSB stream across row 0 yields:
  `0000000000010111011100100011001101100001...`
- Converting to bytes:
  - `\x00\x17` (16-bit big-endian length = 23)
  - Followed by 23 ASCII bytes: `r3ad_b3tw33n_th3_p1x3ls` ("read between the pixels").

### 3. Decrypting the Archive
Using `r3ad_b3tw33n_th3_p1x3ls` as the passphrase to decrypt the trailing ZIP archive:
- `README.txt`: *"You found the second truth AND the key. Nicely done."*
- `flag.txt`: `csaw{0n3_f1l3_tw0_truth5_p0lygl0t_m4g1c}`

The flag confirms the polyglot and steganographic nature of the challenge.

# Keep Digging

- **Category:** Steganography
- **Points:** 100
- **Flag:** `deadface{D1g_d0wN_D33p!}`

## Challenge

<honeypot-string-withheld> DEADFACE left this calling card on a victim's machine. We suspect there is hidden information in this image, but none of our common steganography tools seem to work. There must be some way to determine where the flag is hidden. Submit the flag as `deadface{flag-text}`. [Download Image](https://deadface.sfo3.cdn.digitaloceanspaces.com/2026/challenges/steg/steg06/keep_digging.jpg) SHA256: `12582c19c665ee4c7c8d4517ccb8f3559356620553970b235d8aad4e0b4ff8e2`

## Solution

REPRODUCIBLE: keep_digging.jpg is progressive 448x670 with 7795 bytes of valid entropy data beyond the declared MCUs (7 scan boundaries; libjpeg: 'extraneous bytes before marker'), i.e. the artwork is TALLER than the SOF says. Patch SOF2 height at file offset 176 (0x04A2) from 670 to 790, decode, and rows 670-766 render 'deadface{D1g_d0wN_D33p!}' in teal on dark.jpg,tall.png,bottom_crop.png}; original sha256 12582c19c665ee4c7c8d4517ccb8f3559356620553970b235d8aad4e0b4ff8e2.

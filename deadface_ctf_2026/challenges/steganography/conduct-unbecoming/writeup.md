# Conduct Unbecoming

- **Category:** Steganography
- **Points:** 75

## Challenge

DEADFACE recently breached Night Veil University and exfiltrated a number of internal documents. We were able to recover one of those documents for analysis. We need your help to identify the asset-id that was used to create the document so we can have our investigators analysis it for more clues on how DEADFACE gained access. Submit the flag as `deadface{flag-text}`. [Download Image](https://deadface.sfo3.cdn.digitaloceanspaces.com/2026/challenges/steg/steg03/Doc_20261017_0915.jpg) SHA256: `6e7809f4a7893b0a8348195d0009181376ef635d465a2ee4279e78115e44f1ba`

## Solution

CONFIRMED | Independent re-derivation by the team: own blob detection on yellow-ness min(R,G)-B found a 13x8 dot field at y 3026.5-3170.6, x 2331.5-2415.2, dy=12.01 dx=11.95; row0=0xFF sync, rows1-12 decode MSB-first to NVU-PRINT-17. Did not run the team's solve.py. Ruled out competing candidates: exiftool -a -G1 -u -U shows no id/asset/serial/uuid/document tag, and 0 bytes trail the JPEG EOI, so the MIC grid is the only asset-id in the file. Semantics fit: NVU = Night Veil University, PRINT-17 = printer asset tag, and the question asks what created the document. | the team

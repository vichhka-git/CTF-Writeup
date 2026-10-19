# Chess Key

- **Category:** Cryptography
- **Points:** 200
- **Flag:** `deadface{cH3ckM8_ch3s5_cryPt0}`

## Challenge

Looks like DEADFACE compromised a machine and left this cryptic calling card: ``` checkmate. nZ3ipU8_yy3p5_hvyKi0 ``` One of our other analysts also found this image that we believe is tied to this calling card. [Download PNG](https://deadface.sfo3.cdn.digitaloceanspaces.com/2026/challenges/crypto/crypto05/chesskey.png)(821KB) SHA256: `583450106b366b832250ee0dc30d57a055b27772387801d6dc77db9515cd354b` Use this image and any information you can find in GhostTown to reveal the flag. Submit the flag as `deadface{flag-text}`.

## Solution

Cached English-opening Carlsen PGN 162638222425 plus chesskey.png gives key LSGFIWRXFEAVPXDCHDDB; case-preserving A-Z Vigenere decrypts and round-trips exactly.

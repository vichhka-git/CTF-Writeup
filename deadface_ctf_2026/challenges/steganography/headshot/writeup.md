# Headshot

- **Category:** Steganography
- **Points:** 10

## Challenge

DEADFACE was able to compromise a fileshare that consisted of corporate headshots for Aurora Health employees. We believe they're tagging the photos with information that communicates to their group which employees to target in their future campaigns. Figure out which image DEADFACE tampered with - it will give us a heads up on who they plan to target. Submit the answer as `deadface{flag_text}`. [Download ZIP](https://deadface.sfo3.cdn.digitaloceanspaces.com/2026/challenges/steg/steg01/headshot.zip) SHA1: `5c6572a3ab5a10e682ba479009ee57418d455d7ac678cd6041c54f7a50c40bc9`

## Solution

The challenge provides a zip archive (`artifacts/headshot.zip`) containing Aurora Health corporate headshots and states that DEADFACE tagged one of the photos to communicate target selection. Running metadata analysis with `exiftool` reveals a PNG `Comment` metadata field embedded in `headshot003.png` containing the flag `deadface{b00m_h34Dsh0TTT}`.

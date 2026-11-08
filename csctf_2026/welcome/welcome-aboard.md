# Welcome Aboard

**Category:** Welcome · **Points:** 100 · **Flag:** `CSCTF{w3lcome_aboard_operator_a17f}`

## What the handout gives you

The README presents a first transmission as an encoded string and asks the operator to decode it. The string uses the standard Base64 alphabet and ends in `=`, the padding marker used when the final input group contains fewer than three bytes. There are no separate attachments.

- `README.md` contains the encoded transmission and the required `CSCTF{...}` flag format.

## Walkthrough

1. Copy the entire transmission from the README exactly: `Q1NDVEZ7dzNsY29tZV9hYm9hcmRfb3BlcmF0b3JfYTE3Zn0=`. Its letters, digits, and final equals sign match standard Base64 syntax. Decoding converts groups of Base64 characters back into bytes, with no key required.

2. Decode the text with a Base64 decoder. On a Unix-like terminal, one short command is `printf '%s' 'Q1NDVEZ7dzNsY29tZV9hYm9hcmRfb3BlcmF0b3JfYTE3Zn0=' | base64 -d`. The output is readable ASCII. Preserve the trailing `=`; it tells the decoder that the last group has two output bytes rather than three.

3. Check the group boundaries if you want to verify the result by hand. Each quartet represents 24 bits: four six-bit alphabet values. Those bits become three bytes, except for the padded final quartet. The quartets decode as follows:

| Base64 quartet | ASCII bytes |
| --- | --- |
| `Q1ND` | `CSC` |
| `VEZ7` | `TF{` |
| `dzNs` | `w3l` |
| `Y29t` | `com` |
| `ZV9h` | `e_a` |
| `Ym9h` | `boa` |
| `cmRf` | `rd_` |
| `b3Bl` | `ope` |
| `cmF0` | `rat` |
| `b3Jf` | `or_` |
| `YTE3` | `a17` |
| `Zn0=` | `f}` |

To check the first row, the Base64 indices for `Q`, `1`, `N`, and `D` are 16, 53, 13, and 3. Their six-bit forms join as `010000110101001101000011`, which splits into bytes `01000011 01010011 01000011`, or ASCII `CSC`. This confirms the first three decoded characters without relying on the printed flag.

The last quartet has only three Base64 symbols before padding. `Z`, `n`, and `0` have indices 25, 39, and 52. Their first 16 joined bits are `01100110 01111101`, which are ASCII `f}`. Padding discards the incomplete final byte, leaving two output characters for this group.

4. Read the decoded groups continuously. They form `CSCTF{w3lcome_aboard_operator_a17f}`. Keep the digit `3` in `w3lcome`; it is part of the decoded text, not a typo to normalize. The underscores and braces also come directly from the ASCII output. The opening `CSCTF{` and final `}` match the wrapper format in the README.

## Answer

The transmission is Base64-encoded flag text. Decoding it yields `CSCTF{w3lcome_aboard_operator_a17f}` exactly.

# Digital Design

- **Category:** Cryptography
- **Points:** 100
- **Flag:** `deadface{BINARYLOGIC}`

## Challenge

Investigators found a post by `lilith` on Ghosttown that looks like some new crazy encryption scheme but they can't make heads or tails of it. Find the post with a large binary string and an alphabetic string that contains the letters `A`, `O`, `N`, and `X` and see if you can break the code. Submit the answer as `deadface{FLAGTEXT}`.

## Solution

REPRODUCIBLE: GhostTown /t/51/four-letters-still-too-many-for-you (lilith, 7d ago). For each of the 11 groups, feed the binary group's bits left-to-right into the gate group's letters left-to-right, with A/O/X as 2-input AND/OR/XOR and N as 1-input NOT; the per-group arity sums equal the bit-group lengths exactly (9,8,9,9,9,9,9,8,8,9,10), which is the proof the pairing is right. Each group yields 5 output bits; A=1 letter indexing (bit5=MSB) gives the phrase.html + decode.txt.

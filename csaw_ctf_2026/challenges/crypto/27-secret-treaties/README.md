# Secret Treaties

- Category: Crypto
- ID: 27
- Type: dynamic
- Value: 50
- Solves: 276
- Author: WubberDuckkie
- Files:
  - `files.zip`

## Description

We built a "quantum-resistant" public-key scheme from the good old subset-sum problem. Subset-sum is NP-complete, so surely nobody can read our messages without the private key... right?

We encrypted the flag nine bytes at a time. Each 72-bit block became a single number: the sum of the public-key entries selected by that block's bits.

Recover the flag.

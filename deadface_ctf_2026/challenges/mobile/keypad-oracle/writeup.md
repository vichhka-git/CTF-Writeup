# Keypad Oracle

- **Category:** Mobile
- **Points:** 200

## Challenge

We’ve infiltrated DEADFACE’s development pipeline and extracted an iOS application currently under development. We've successfully run it using an iOS Simulator, but can't break the code. Can you use your skills to figure out the secret message? Enter the flag as text: `deadface {flag_text}`. [Download ZIP](https://deadface.sfo3.cdn.digitaloceanspaces.com/2026/challenges/mob/mob05/Keypad-Oracle.app.zip)(80KB) SHA256: `7bfda8f6fa3bebbe29a6e18c4312a29ec9a3cdfda394eb01d39a59df849af49e`

## Solution

CORRECTION - CONFIRMED deadface{your-pin-is-valid}, PIN 3719. the team was RIGHT and my "fabricated" call was WRONG | I earlier marked this DISPUTED because grepping all three binaries for "your-pin"/"deadface" returned nothing, and concluded the team invented the flag. That inference was invalid: the flag is never stored as a literal - it is COMPUTED at runtime, which is the entire point of the challenge. Completing the reverse proves the team's answer exactly. Full verified chain: PinCipherEngine has three private properties - outputLength (28), binarySalt (28 bytes, hardcoded in its property initializer at 0x19e4: 3a 91 44 2f d0 18 6b c3 72 0e a9 5d 11 be 80 27 f4 66 39 9a 05 cc 70 1b 88 42 e1 53) and seedTable (loaded from KeypadConfig.json: ten 27-byte seeds, one per digit). encode(pin:) requires 4 digits with no repeats, then acc = XOR over positions of derive(seed:digit:position:), then acc ^= binarySalt, returned as hex. derive builds 28 bytes, wrapping the 27-byte seed with i % seed.count:

# Just Give Me The Flag Man

Just Give Me The Flag Man is a cryptography challenge worth 60 points (269 solves). The attachment is a single line of 52 two-character tokens and nothing else. It is not a substitution cipher over the tokens. It is a stack of encodings that has to be undone in the right order, with two letter permutations folded in.

## What you are given

`chall.zip` unpacks to `chall.txt`, one line of 52 space-separated tokens beginning

```
53 74 u3 17 35 x3 x2 76 ...
```

and ending `... 45 v5 93 x2`. No service, no source and no key. The team's submission log records this one as a portal solve from before the submission gate existed, so there is no gate response to quote; a later workspace pass derived the same string from the artifact and proved it by exact inverse reconstruction.

## Reproduction

1. Look at the alphabet before guessing at ciphers. The first characters of the 52 tokens come from `{0-9, u, v, w, x, z}` and the second characters from `{2..7}`. There are 35 distinct tokens. The six letters are exactly the alphabet-Atbash images of `{a, c, d, e, f}`: `u` to `f`, `v` to `e`, `w` to `d`, `x` to `c`, `z` to `a`. The missing hex letter is `b`, which would come from `y`, and `y` never appears.

2. Apply Atbash to letters only. `u` to `f`, `v` to `e`, `w` to `d`, `x` to `c`, `z` to `a`; digits unchanged. After this every token is two hex digits, which is the first hard constraint that the reading satisfies.

3. Reverse each two-character token and concatenate. The result is 104 hex characters and decodes to 52 printable ASCII bytes. Recorded intermediates for these two stages:

   ```
   hex   : 35473f71533c2c674233393f614e634e392346223a2c244d45502e5e366e62326233683f333c472c6045265c22474440545e392c
   ASCII : 5G?qS<,gB39?aNcN9#F":,$MEP.^6nb2b3h?3<G,`E&\"GD@T^9,
   ```

   The backslash before the quote is a real backslash byte, not escaping.

4. Reverse those 52 bytes. The order matters because the next layer is position sensitive:

   ```
   ,9^T@DG"\&E`,G<3?h3b2bn6^.PEM$,:"F#9NcNa?93Bg,<Sq?G5
   ```

5. ASCII85-decode that 52-character string, using the standard alphabet without the Adobe `<~ ~>` delimiters. Fifty-two characters is a legitimate ASCII85 length: ten complete four-byte groups give 50 characters and the single leftover byte gives two more. The output is 41 bytes:

   ```
   #!dvnJk6rRHc9"NB7NnI*/1##$!DLYv$^:z3#<Tjw
   ```

6. Apply ROT47, the rotation over the 94 printable ASCII characters, that is `chr(33 + (ord(c) - 33 + 47) % 94)`:

   ```
   RP5G?y<eC#w4hQ}qf}?xY^`RRSPs{*GS/iKbRk%;H
   ```

7. basE91-decode that. Use the standard basE91 alphabet, which is the uppercase letters, the lowercase letters, the ten digits, and then the twenty-eight punctuation characters in the order given by the published table (it ends with `{|}~"`). The accumulator takes 13 bits when the pending value exceeds 88 and 14 bits otherwise, and a leftover character contributes one final byte. The output is 33 bytes:

   ```
   feKTH{uf1ht1zg_7fv0sgf_7f3_l4u3u}
   ```

8. Undo the final letter permutation. The prefix `feKTH` has to become `hiCTF`. Atbash takes `f` to `u` and ROT13 takes `u` to `h`, so the composed map is Atbash followed by ROT13. For a zero-based letter index `c` the output index is `(12 - c) mod 26`, with case preserved and every non-letter unchanged. Applied to the whole 33-byte string:

   ```
   hiCTF{sh1ft1ng_7hr0ugh_7h3_b4s3s}
   ```

9. Prove it by inversion rather than by readability. Run the chain backwards: apply the same letter reflection, basE91-encode, ROT47, ASCII85-encode, reverse the 52 bytes, hex-encode, split into two-character tokens, reverse each token, and Atbash the letters. The result must equal `chall.txt` byte for byte, including the trailing newline. The workspace record is `ROUNDTRIP_EXACT: True`, and that reconstruction is what turns a readable-looking string into a demonstrated derivation.

## Why it works

Every layer is a public, keyless encoding, and both letter transforms are fixed permutations with no key. The file contains no secret; it contains a chain, and the entire difficulty is identifying the chain.

The misleading part is the token format. Fifty-two tokens look like a ciphertext over a 35-symbol alphabet, and the earlier workspace attempt spent several rounds on substitution, columnar transposition, fractionated Morse, Braille and book-cipher families before parking the challenge. One observation kills that entire space: the token `x2` appears at index 51, which would have to be the closing brace of a 52-character flag, and also at index 6. No map from token to character can send one token to two different plaintext characters, so the tokens were never symbols. Reading them as nibble pairs, after the Atbash that turns the token alphabet into the hex alphabet, is the pivot. That negative result is worth keeping because it is the reason the obvious approach was abandoned rather than extended.

Once the tokens are nibbles, the order of the middle layers is forced at every stage: hex output is hex, hex decode gives printable ASCII, the reversed 52 bytes are a valid ASCII85 length, and the ASCII85 output is a valid basE91 string. None of those steps needed a search.

## Flag

```
hiCTF{sh1ft1ng_7hr0ugh_7h3_b4s3s}
```

# Cipher Cascade

Cipher Cascade is a cryptography challenge worth 53 points (879 solves). A short intercepted message is wrapped in four layers of keyless encoding. The file names the order of the outer three layers and leaves the innermost one unnamed.

## What you are given

`cipher-cascade.zip` unpacks to `cipher_cascade.txt`, 309 bytes of text with a five line header and a 76-character payload. No service and no key material.

## Reproduction

1. Read the header. It states the peel order and names three of the four layers:

   ```
   Layers applied (outermost to innermost): Reverse -> Base64 -> Hex -> ???
   ```

   The payload is reversed last, so it must be un-reversed first, then base64-decoded, then hex-decoded, then passed through the unknown layer. The payload is

   ```
   =Q2NxcTM2EzMhZTM2gjNmVTN2MzMjZDNzkzNmVzY2YmNmVTN2MzMjZDNzkzNidzM1cDNwUjN3UzN
   ```

   Note the leading `=`. A pad character at the front is wrong for a forward base64 string and exactly right for a reversed one, which is the first sign that the reversal belongs to this text and not to the header.

2. Reverse the 76 characters:

   ```
   python3 -c "s=open('cipher_cascade.txt').read().split('Encoded message:')[1].strip(); print(s[::-1])"
   ```

   ```
   NzU3NjUwNDc1MzdiNzkzNDZjMzM2NTVmNmY2YzVmNzkzNDZjMzM2NTVmNjg2MTZhMzE2MTcxN2Q=
   ```

   The pad is now at the end, where base64 wants it. That is independent confirmation rather than a plausible-looking alphabet.

3. Base64-decode. The output is 56 characters, all in `[0-9a-f]`, which is what the next named layer expects:

   ```
   75765047537b79346c33655f6f6c5f79346c33655f68616a3161717d
   ```

4. Hex-decode to 28 bytes:

   ```
   uvPGS{y4l3e_ol_y4l3e_haj1aq}
   ```

   The shape is already a flag, but the prefix is `uvPGS` and not `hiCTF`.

5. Resolve the unnamed layer from format rather than by search. A single fixed letter transformation has to carry `uvPGS` to `hiCTF` character for character, and ROT13 does exactly that: `u` to `h`, `v` to `i`, `P` to `C`, `G` to `T`, `S` to `F`. Applying ROT13 to all 28 bytes,

   ```
   python3 -c "import codecs; print(codecs.encode('uvPGS{y4l3e_ol_y4l3e_haj1aq}', 'rot13'))"
   ```

   gives the answer. Two nearby guesses are worth ruling out explicitly. Alphabet Atbash maps `uvPGS` to `feKTH`, which has the right shape and the wrong letters, so the layer is a rotation and not a reflection. A single-byte XOR would need the diffs `[29, 31, 19, 19, 21, 0]` to turn `uvPGS{` into `hiCTF{`, and those are not constant, so no fixed key exists there either.

6. Read the body as the second confirmation. `l4y3r_by_l4y3r_unw1nd` is readable English in leetspeak and it describes the challenge itself: layer by layer, unwind. A layer guessed from a five-character prefix could still mangle the body, and here the body and the prefix agree.

## Why it works

Nothing here is encryption. Reverse, base64 and hex are fixed, keyless, invertible transformations, and ROT13 is a fixed rotation over a 26-letter alphabet. The four layers together contain no secret, so the whole thing collapses once the order is known, and the order is printed in the file. The remaining work is recognising the family of each stage: the leading base64 pad after reversal, an all-hex intermediate, and 28 bytes whose first five characters are a ROT13 image of the event prefix.

The reason it still takes a minute is that the innermost layer has three plausible candidates and only five characters of known plaintext to test them against. The body text is what turns that into a judgement rather than a guess, and it is also why the challenge is scored low.

## Flag

```
hiCTF{l4y3r_by_l4y3r_unw1nd}
```

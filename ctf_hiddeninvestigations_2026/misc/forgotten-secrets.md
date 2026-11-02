# Forgotten Secrets

Forgotten Secrets was a 54 point misc challenge (626 solves in the local record). It hands over a single 256 KiB memory image and warns that the flag will not appear in a string search. Everything readable in the dump is bait; the real payload sits between two hexadecimal markers and is masked with a one byte XOR.

## What you are given

- `forgotten-secrets.zip` containing `forgotten_secrets.bin`.
- The binary is exactly 262,144 bytes (0x40000), whole file entropy 7.99756 bits per byte, with 4 KiB block entropies between about 7.931 and 7.965.

No service, no host, no credentials. The challenge is offline and needs only a hex viewer and Python.

## Reproduction

1. Look at the file type before anything else. `xxd -l 64` shows `7f454c4602010100...`, a forged ELF identification prefix. The header does not survive inspection: `e_machine` is 0xc4aa, `e_ehsize` is 25,745 instead of 64, and `e_phoff` (0xa0577eeb3cb4099f) and `e_shoff` (0x1bd02416226687ea) both point past end of file. `file` labels it ELF on the magic alone. The header is a prop, so stop treating the file as a program.

2. Run a string search and read what it produces. `strings -n 20` returns, among other things, `root:x:0:0:...`, `Authorization: Bearer <decoy token>`, `AES-256-CBC encrypted block follows`, `base64_encoded_nothing_useful_here`, a bogus password line, and `This is not the flag you are looking for`. The flag text itself is absent, and none of these strings has a matching key, IV, padding, or container. They are planted decoys, including the AES claim.

3. Search for structure instead of vocabulary. Two ASCII markers bracket every record: the eight bytes `DEADBEEF` (`4445414442454546`), then a body, then the eight bytes `CAFEBABE` (`4341464542454245`). There are 22 `DEADBEEF` hits. The first record starts at 0x231d6 and the last start marker is at 0x3e1da. Each record is 43 bytes: 8 marker, 27 body, 8 marker.

4. Read one body and compare it with the known flag prefix. At 0x231de the body begins `2a 2b 01 16 04 39 ...`. XOR the first six bytes with `hiCTF{` (`68 69 43 54 46 7b`) and every one of them gives 0x42.

   ```
   2a ^ 68 = 42
   2b ^ 69 = 42
   01 ^ 43 = 42
   16 ^ 54 = 42
   04 ^ 46 = 42
   39 ^ 7b = 42
   ```

   The key falls out of the known plaintext prefix, so there is no key-space search.

5. Decode a body with that key. The full 27 byte body is `2a2b011604392f712f72303b1d26372f321d2673251d267171323f`. Applying XOR 0x42 to each byte yields `hiCTF{m3m0ry_dump_d1g_d33p}`.

6. Check the other 21 records. Every body is byte for byte identical, so all 22 decode to the same 27 byte string. That repetition is the corroboration: a single accidental marker pair in 256 KiB of random data would be plausible, 22 of them with identical bodies is a planted answer.

7. Confirm the transformations that do not work, so the result is not a coincidence. The local record ruled out plain, reversed, ROT13, hex, Base64 and Base32 of `hiCTF{`, UTF-16LE, UTF-16BE and UTF-32LE encodings, null byte interleaving at strides 1 to 8, nibble swap, bit reversal, and byte complement. It also confirmed there is no data after the file trailer, since the file ends exactly at 0x40000.

The local notes record the marker offsets, the 27 byte body, the key 0x42, and the 22 record count. They do not record every individual marker offset beyond the first at 0x231d6 and the last start at 0x3e1da.

## Why it works

A single byte XOR is not encryption. It survives only because a string search over the file sees noise, and the author surrounded the payload with readable decoys that look like incident response material. The markers do the work that encryption would otherwise do: they tell you exactly where to look, and once you are looking at a record, the fixed `hiCTF{` prefix gives you the key in one subtraction. The same key then decodes the whole message.

The high entropy of the background is a red herring. It belongs to random filler, not to a cipher, and the 27 byte records are far too short to be a block cipher without padding.

## Flag

```
hiCTF{m3m0ry_dump_d1g_d33p}
```

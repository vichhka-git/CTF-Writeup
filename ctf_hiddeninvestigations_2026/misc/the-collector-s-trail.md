# The Collector's Trail

The Collector's Trail was a 66 point misc challenge (188 solves in the local record). It is a chain: identify six paintings from prose descriptions, find each one in its museum's official collection record, pull a fragment out of each image with a different carrier, then use the fragments and the catalogue identifiers to derive keys for a sealed cabinet and a final encrypted record.

## What you are given

- `the-collectors-trail.zip` containing `image_vault.zip` and `sealed_cabinet.zip`.
- The image vault holds six record directories (`record-7f2a`, `record-b19d`, `record-31c8`, `record-d604`, `record-5a73`, `record-e2f1`), each with a file named `image` and a short `conservation.txt` note, plus `catalogue/colophon.txt`, which is the specification for fragment validation and key derivation.
- The sealed cabinet is a password protected zip with two members, `readme.txt` and `stego.png`.

No service and no login material. The only network use is reading public museum collection pages and one public release asset.

## Reproduction

1. Read `colophon.txt` first. It defines the fragment form `<16 hex>-<4 hex>`, the seal rule (SHA-256 over the eight decoded bytes, first two digest bytes as lowercase hex must equal the check value), the HKDF parameters for the master key, the locator normalisation rules, and the cabinet password derivation. It also says the steghide passphrase for one object is the complete canonical locator, not the accession number.

2. Identify the six works from the descriptions. They are Vermeer's Girl with a Pearl Earring, Goya's The Third of May 1808, van Gogh's The Starry Night, Klimt's The Kiss, Munch's The Scream, and Schiele's Death and the Maiden. The last one is pinned by the year 1918 in the text.

3. Pull the exact identifier from each museum's own record, not from a search snippet. The recorded values are:

   ```
   Mauritshuis      inventory 670          mauritshuis.nl/670
   Museo del Prado  inventory P000749      museodelprado.es/P000749
   MoMA             object 472.1941        moma.org/472.1941
   Belvedere        inventory 912          belvedere.at/912
   National Museum  inventory NG.M.00939   nasjonalmuseet.no/NG.M.00939
   Belvedere        inventory 3171         belvedere.at/3171
   ```

   The exact strings matter. The Prado record uses `P000749`, MoMA calls its field an object number, and the Belvedere titles are "The Kiss (Lovers)" and "Death and Maiden". A locator built from a different spelling produces a different catalogue digest later.

4. Extract one fragment per image. Each carrier is different, and the colophon's warning about copies is literal: re-encoding or resampling an image destroys the payload.

   ```
   record-7f2a  private PNG chunk "coLl", 21 bytes
   record-b19d  30 bytes after the PNG IEND chunk, Base64 wrapped
   record-31c8  text in the fully transparent border, visible when alpha is forced opaque
   record-d604  JPEG, steghide with the full locator as passphrase
   record-5a73  blue channel LSB at flattened pixel indices 0, 7, 14, ...
   record-e2f1  first 176 PNG row filter bytes, map 1 to 0 and 2 to 1, pack MSB first
   ```

   For `record-e2f1` the packed bits start with a `0x15` byte that is not part of the fragment; skip it. For `record-5a73` the fragment starts at byte 1 of the packed stream.

5. Validate every fragment against its seal before using it. The six that pass are:

   ```
   I    be5f329a4841bece-ee99
   II   b086be35786cac71-8ab3
   III  c1d322deee71edf2-cfb8
   IV   07961017e80fb1e3-b14e
   V    7141415e3a146329-c2dc
   VI   74718896e450c77c-e551
   ```

   One real pivot here: the Belvedere collection page lives under a `sammlung.` subdomain, and using `sammlung.belvedere.at/912` as the steghide passphrase produced a fragment that failed its seal. The base domain form `belvedere.at/912` produced the fragment above, and its seal validates. The colophon's normalisation rule (lowercase base domain, no scheme, no `www.`) is what selects the right string.

6. Order by artist birth year. The order is already I to VI: Vermeer 1632, Goya 1746, van Gogh 1853, Klimt 1862, Munch 1863, Schiele 1890. Decode each fragment to its eight raw bytes, drop the check values, and concatenate in that order. The joined bytes hash to `006e4b303cc14663084d3582c58430d13bde85f40d9166e62a467a5e1c276e51`.

7. Derive the master key with HKDF-SHA256 over the joined bytes, salt `collector-v2:ossuary`, info `master`, 32 bytes. The result is `bbb26315a1493bc6e013364b1ccf78ecb7bcc2a3aeb3972f2885f9b2b444b9bf`.

8. Build the catalogue salt. Join the six canonical locators with single line feeds in the same birth year order, no leading or trailing newline, UTF-8 encode, SHA-256. The digest is `40762afb7192c838fccba2284ebcb0b760da6a35698d4c6d0fb2da17088f46b1`.

9. Derive the cabinet password: HKDF-SHA256 with the master key as input key material, the raw 32 byte catalogue digest as salt, info `zip`, 16 bytes, written as 32 lowercase hex characters. That gives `77dad76b506abec33742bc43b14710e4`. Open the cabinet with it. The WinZip AES integrity test passes and both members decrypt.

10. Read the cabinet's `readme.txt`. It specifies the image key: HKDF-SHA256 with the master key as input, an empty salt (zero length, not the word), info `stego`, 32 bytes. It also specifies the collector's index: for counter 0, 1, 2, ... compute HMAC-SHA256 with the image key over the counter as an eight byte big endian integer, take the first eight digest bytes as a big endian integer, reduce modulo the number of RGB byte positions in the image, and take the LSB of that byte. Skip a position that was already selected without consuming a bit. Pack the bits MSB first.

11. Apply that to `stego.png`. The image has 6,220,800 RGB byte positions. The frame is a four byte big endian length, then the payload, then a four byte CRC-32 over the payload. The declared length is 451, the stored CRC is `1cc2b9d2`, and the computed CRC matches. The payload names a public GitHub repository, release tag `v1.0`, and asset `flag.enc`, states that the asset is in the release rather than the repository tree, gives its SHA-256 as `cf9932777723fb3b768006dc21bb832baf3cfa6ffba59c8d84f43f095e3e4bb4`, and says the serial is in the tag's note.

12. Fetch the annotated tag object for `v1.0` and read the note. It ends with `Serial: 1ec5d6c0778858ef9bd8e651ef1efeae`. Download the release asset and check the hash against the payload before using it; the 82 byte asset matches.

13. Derive the final key and decrypt. The payload gives the recipe: `flag_key = HKDF(master, salt=bytes.fromhex(serial), info=b"flag", L=32)`, then AES-256-GCM over `nonce(12) || ciphertext || tag(16)` with AAD `collector-v2`. The derived key hashes to `b48752ebf22725c468e1f857ae5f918739f1168a7506737de73d1909163a9ddd`, authentication passes, and the plaintext is 54 bytes.

The local notes record the fragment strings, the seals, the master key, the catalogue digest, the cabinet password, the payload length and CRC, the serial, and the asset hash. They do not record the individual HMAC counter values that produced the 3,672 selected positions, only the count and the final frame.

## Why it works

Every stage is a check on the previous one, and the checks are cryptographic rather than visual. The seal on each fragment means a wrong carrier or a re-encoded copy is rejected immediately instead of silently poisoning the master key. The catalogue digest means a wrong accession identifier changes the cabinet password, so a plausible looking record is not enough. The CRC on the stego payload and the SHA-256 on the release asset do the same job at the end.

The design mistake being exploited is the assumption that a picture is only its visible content. The fragments live in a private PNG chunk, in bytes after IEND, in the RGB values of a fully transparent border, in JPEG steghide data, in the blue channel LSB, and in PNG row filter bytes. None of that survives a screenshot, a resize, or a re-save, which is exactly what the collector's warning says.

## Flag

```
hiCTF{marble_sparrow_9eb44602eedb764aac082a3816b7d7cb}
```

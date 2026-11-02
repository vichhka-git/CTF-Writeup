# Paper Trail

Steganography, 60 points, 271 solves. A thirteen page academic PDF that looks unmodified.
Four of its pages carry a second, extra content stream that draws nothing, and the
positioning numbers inside those streams are the payload. Sixty four bytes come out, and
the document's own trailer identifiers are the AES key and IV.

## What you are given

`paper-trail.zip` expands to a single file, `chall.pdf`, 516,033 bytes. There is no live
service and no login material.

## Reproduction

1. Count the pages. `file` reports six, but the page tree resolves to thirteen:

   ```sh
   python3 -c 'from pypdf import PdfReader; r=PdfReader("chall.pdf"); print(len(r.pages)); print(r.trailer)'
   ```

   The trailer is a single, ordinary one: `/Size 183`, `/Root 1 0 R`, `/Info 178 0 R`,
   and an `/ID` pair. There is exactly one `startxref`, it points at offset 512211, and
   there is one `%%EOF`. The single `/Prev` in the file belongs to an outline object, not
   to an incremental update trailer.
   The cover content is a real journal article, "Journal of Digital Forensics, Security
   and Law" volume 12 number 1, so the visible document is a genuine carrier.

2. Look at the `/Contents` arrays, because that is where the extra streams hide. Four
   pages have a second element appended to the array instead of replacing anything:

   ```
   page 3  (object 52) -> [53, 179]
   page 6  (object 61) -> [62, 180]
   page 9  (object 72) -> [73, 181]
   page 12 (object 86) -> [87, 182]
   ```

   The appended objects sit at raw offsets 0x7cd46, 0x7ce37, 0x7cf2c and 0x7d016. Nothing
   in an xref, an incremental update or an orphan object explains them.

3. Decode the four appended Flate streams. Their decoded lengths are 295, 294, 256 and
   165 bytes, and all four begin with the same prologue:

   ```
   q BT /F1 1 Tf 3 Tr 1 0 0 1 8 8 Tm
   ```

   `3 Tr` sets text render mode 3, which draws nothing at all. Every `TJ` array in these
   streams contains only empty strings `()` and numeric positioning operands, so there
   is no visible or extractable text anywhere in the hidden streams.

4. Collect the numbers and separate the two populations. There are 20 `TJ` rows across
   the four objects (6, 6, 4 and 4) holding 169 numbers in total, ranging from -77 to
   254. Exactly three rows are long: object 179 row 3 with 21 numbers, object 180 row 3
   with 21, and object 181 row 2 with 22. Those 64 values are all in the range 0 to 255
   and look like bytes. Every other row holds small signed adjustments, and the first
   two numbers of each row are framing.

   ```python
   rows = [[int(x) for x in re.findall(rb"-?\d+", a)] for a in arrays]
   ct = bytes(v for row in long_rows for v in row[2:])   # 64 bytes
   ```

   The payload is:

   ```
   ae045988164c448a8e560c5292da7f1722a9c9018e15cb606e10ebb2a27c5944
   189f3d75269e3abc0167fa87efa9fe08b0eb74433b0c82d8b5d7f4d5b02139f6
   ```

5. Take the key material from the trailer. The two `/ID` strings are:

   ```
   /ID [ <e3b51a3ba231502d79c55593eb522037> <6749db1175e3e659a640695dcc830c82> ]
   ```

   Each is 16 bytes, which is exactly AES-128 key and IV length. The convention that
   falls out of the byte count is key = `/ID[0]`, IV = `/ID[1]`, and the 64 payload bytes
   are four cipher blocks.

6. Decrypt with AES-128-CBC:

   ```python
   AES.new(id1, AES.MODE_CBC, iv=id2).decrypt(ct)
   ```

   The plaintext is:

   ```
   b'CTF1\x00(hiCTF{n3w_ar34_fOr_hid!ng_d4t4_n4m3d_TJ}\x90\x8a\x1a\x00\n\xd4\xb3l\n\n\n\n\n\n\n\n\n\n'
   ```

   The structure is a six byte header, `CTF1` plus a null, then the byte `0x28`, which is
   both the character `(` and the value 40, matching the length of the flag that
   follows. The text is exactly 40 bytes, then eight bytes of trailing metadata and ten
   bytes of `0x0a`, which is valid PKCS#7 padding of length 10 for a 64 byte block.
   Reading the 0x28 as a length field gives the flag length on the nose, which is the
   check that the key, IV and byte order are all correct.

## Why it works

A PDF content stream list is an array, and appending an element adds rendering work
without removing or changing anything already there. Because the appended streams set
render mode 3, they contribute nothing visible, and because their text arrays hold only
positioning numbers and empty strings, ordinary text extraction returns the article and
stops. The payload never becomes glyphs, so there is nothing to read; it exists only as
numeric operands whose magnitude happens to be byte sized.

The key material is not hidden at all. `/ID` is a mandatory looking trailer field that no
analyst normally inspects, and the author reused its two 16 byte values directly as the
AES key and IV. There is no key derivation and no nonce management, so a correct guess
about the convention decrypts the whole payload in one step.

## Flag

```
hiCTF{n3w_ar34_fOr_hid!ng_d4t4_n4m3d_TJ}
```

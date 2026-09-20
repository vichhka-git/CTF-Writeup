# Writeup: SQ_NOTICE10: The Palette That Did Not Change

- **CTF**: Singapore Cyber Conquest 2026
- **Category**: Forensics / Stego
- **Points**: 450
- **Status**: Solved
- **Flag**: `flag{n0t1c3_t3n_214f610b3d}`

---

## 1. Challenge Overview

We are given:
- `NOTICE10.PCX`: The current reissued PCX image (320x200, 16-color EGA palette).
- `NOTICE10.BAK`: The retained prior copy of the image.
- `NOTICE10.TXT`: 16 numbered paragraphs, where each line body begins with a 16-character string.
- `PALSWAP.DOC`: Documentation describing how PALSWAP stores palette entries in edit order, how to extract the 16-character designation from the notice text against the edit order table, verify with CRC-32 (`0x34887E5B`), and decrypt the sealed 27-byte clearance block using repeating XOR with the designation, verified with CRC-32 (`0xE2021920`).

---

## 2. Analysis & Mechanism

1. **Palette Comparison**:
   In PCX 16-color files, the 16 RGB entries are stored in the header at offset 16 (48 bytes). Comparing `NOTICE10.PCX` (current) and `NOTICE10.BAK` (prior):
   Both files have identical image dimensions and visual artwork, but the palette slots are permuted in edit order.
   Mapping each entry index $i$ in `NOTICE10.PCX` to its corresponding color position $j$ in `NOTICE10.BAK` yields the station permutation:
   `[1, 9, 11, 5, 10, 4, 2, 15, 12, 3, 13, 7, 14, 8, 6, 0]`.

2. **Designation Extraction**:
   For each paragraph $i \in [0, 15]$, we read column $c = \text{permutation}[i]$ from the line body (0-indexed from the start of the body text).
   Extracting the character at index $\text{permutation}[i]$ from each of the 16 paragraphs yields:
   `SILENTTERMINAL38`
   CRC-32 of `"SILENTTERMINAL38"` is `0x34887E5B`, matching `SEAL CHK 34887E5B`.

3. **Clearance Block Decryption**:
   The sealed clearance bytes:
   `35 25 2D 22 35 3A 64 31 63 2E 7A 11 35 7F 5D 67 61 78 78 23 78 65 64 27 61 29 34`
   XORing with repeating key `"SILENTTERMINAL38"` produces:
   `flag{n0t1c3_t3n_214f610b3d}`
   CRC-32 of the decrypted string is `0xE2021920`, matching `BLOCK CHK E2021920`.

---

## 3. Solution Script

```python
#!/usr/bin/env python3
import zlib

def read_pcx_palette(filename):
    with open(filename, 'rb') as f:
        data = f.read()
    return [(data[16 + i*3], data[16 + i*3 + 1], data[16 + i*3 + 2]) for i in range(16)]

# 1. Read palettes
pal_cur = read_pcx_palette("NOTICE10.PCX")
pal_bak = read_pcx_palette("NOTICE10.BAK")

cur_to_prior = [pal_bak.index(c) for c in pal_cur]

# 2. Extract designation from NOTICE10.TXT
with open("NOTICE10.TXT", "r") as f:
    lines = [line.strip() for line in f if line.strip() and line.strip()[:2].isdigit()]

para_bodies = [line[3:] for line in lines[:16]]
designation = "".join(body[cur_to_prior[i]] for i, body in enumerate(para_bodies))

assert zlib.crc32(designation.encode('ascii')) == 0x34887E5B
print(f"Designation: {designation}")

# 3. Decrypt clearance block
sealed_hex = "35 25 2D 22 35 3A 64 31 63 2E 7A 11 35 7F 5D 67 61 78 78 23 78 65 64 27 61 29 34"
sealed = bytes.fromhex(sealed_hex)
key = designation.encode('ascii')
clearance = bytes(b ^ key[i % len(key)] for i, b in enumerate(sealed)).decode('ascii')

assert zlib.crc32(clearance.encode('ascii')) == 0xE2021920
print(f"Clearance (Flag): {clearance}")

with open("flag.txt", "w") as f:
    f.write(clearance.strip() + "\n")
```

---

## 4. Flag

```text
flag{n0t1c3_t3n_214f610b3d}
```

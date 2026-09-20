# CSAW CTF Qualifications 2026 Writeup: Finders Keepers!

- **Category:** Crypto / Stego
- **ID:** 10
- **Points / Solves:** 281 pts / 193 solves
- **Flag:** `csaw{y0u_@lw@ys_kn0w_wh3r3_t0_l00k}`

---

## Challenge Summary

The challenge provides a video file `finderskeepers.mp4` with description:
> "I wanna steal everything, but I don't know where it is.... maybe this video can help?"

---

## Solution Steps

### 1. Metadata Inspection
Inspecting the file metadata using `exiftool finderskeepers.mp4`:
```text
Subject: ZXNucHtkMGNfQHl6QGdsX21uMGpfcG0zejNfZzBfbzAwc30=
```
Decoding this Base64 string:
```python
import base64
print(base64.b64decode("ZXNucHtkMGNfQHl6QGdsX21uMGpfcG0zejNfZzBfbzAwc30=").decode())
# Output: esnp{d0c_@yz@gl_mn0j_pm3z3_g0_o00s}
```
The string matches the format of the CSAW flag `csaw{...}` with a substitution / polyalphabetic shift:
- `e -> c` (-2)
- `s -> s` (0)
- `n -> a` (-13)
- `p -> w` (-19 / +7)

The key prefix for the first four letters corresponds to shifts:
`[2, 0, 13, 19] -> 'c', 'a', 'n', 't'` (`cant...`).

### 2. Video Analysis
The video displays an 8-sector wheel in the lower left corner with a central "Spin" button, while semi-transparent pastel rectangles float and obscure sections of the wheel.

By extracting frames and performing polar unwrap or inspecting the wheel as the pastel blocks drift away (specifically around frame 138 at 30 fps), text written along the spoke of the 1 o'clock sector is exposed:
```text
Y2FudGZpbmRpdA==
```
Base64 decoding this text gives:
```python
base64.b64decode("Y2FudGZpbmRpdA==").decode()
# Output: 'cantfindit'
```
This confirms the key is `cantfindit`.

### 3. Decryption
Decrypting the ciphertext `esnp{d0c_@yz@gl_mn0j_pm3z3_g0_o00s}` using the Vigenère cipher with key `cantfindit` (advancing the key only on alphabetic letters):
```text
Ciphertext: esnp{d0c_@yz@gl_mn0j_pm3z3_g0_o00s}
Key:        cant find itca ntfi nditca nt fi ndit
Plaintext:  csaw{y0u_@lw@ys_kn0w_wh3r3_t0_l00k}
```

The flag is accepted by the CSAW scoring server as correct:
`csaw{y0u_@lw@ys_kn0w_wh3r3_t0_l00k}`

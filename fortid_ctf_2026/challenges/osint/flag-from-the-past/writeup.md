# FortID CTF 2026 Writeup: Flag from the Past

- **Category:** OSINT
- **Challenge author:** ipaljak
- **Points / Solves:** 188 pts / 35 solves
- **Flag:** `FortID{H0ard1ng_Fl4gz_4ll_Y3ar_R0und}`

---

## Challenge

> If you stumbled upon one of our flags after last year's contest, now is the
> time to submit it.
>
> If not, I guess you'll just have to use your skills and find it, it should
> still be around... 👀

---

## Summary

The challenge refers to a flag left online after the previous year's event (FortID CTF 2025). The organizers published a wrap-up blog post on their official website (`https://fortid.com/blog/fortid-ctf-2025/`) containing a scoreboard image with its PNG height artificially truncated in the IHDR chunk. Restoring the true height reveals the 6th-place row containing the flag.

## Solution

### Step 1: Discover Post-Contest Organizer Artifacts

The challenge hints that a flag was "stumbled upon after last year's contest". Checking the official FortID website revealed a retrospective blog post:
`https://fortid.com/blog/fortid-ctf-2025/` ("Preparing the FortID CTF").

At the end of the post, the author included:
> "P.S. If you came this far, you must really love CTFs. In that case, maybe you’d like to take a closer look at this blog post, there might be a flag hidden somewhere. And who knows… It might even come in handy a year from now…"

Directly preceding this text was an embedded image: `https://fortid.com/img/wonder_who_got_6th_place.png`.

### Step 2: PNG Height Recovery

The image name explicitly hints at the 6th-place team on the scoreboard, but only places 1 through 5 are visible. Inspecting the PNG chunks and decompressing the `IDAT` stream showed:
- Header dimensions: 2412 x 1472
- Decompressed IDAT length: 11,087,084 bytes
- Given 1 filter byte + 2412 * 3 bytes per scanline (7237 bytes/row), the actual image height is `11087084 // 7237 = 1532`.

By modifying the height field in the `IHDR` chunk from 1472 to 1532 and recalculating the chunk CRC, the bottom 60 scanlines are revealed. The row displays the 6th place entry with the flag text.

### Step 3: Complete Solve Script

```python
#!/usr/bin/env python3
import io
import struct
import subprocess
import tempfile
import urllib.request
import zlib
from PIL import Image

URL = "https://fortid.com/img/wonder_who_got_6th_place.png"

def solve():
    print(f"[*] Fetching scoreboard image from {URL}...")
    req = urllib.request.Request(URL, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req) as resp:
        data = bytearray(resp.read())

    width = struct.unpack_from(">I", data, 16)[0]

    # Decompress IDAT stream to find true height
    idx = 8
    idat_bytes = b""
    while idx < len(data):
        length = struct.unpack_from(">I", data, idx)[0]
        ctype = data[idx+4:idx+8]
        if ctype == b"IDAT":
            idat_bytes += data[idx+8:idx+8+length]
        idx += 12 + length

    decompressed = zlib.decompress(idat_bytes)
    row_bytes = 1 + width * 3
    true_height = len(decompressed) // row_bytes

    # Patch IHDR height and CRC
    struct.pack_into(">I", data, 20, true_height)
    ihdr_data = data[12:12+4+13]
    new_crc = zlib.crc32(ihdr_data)
    struct.pack_into(">I", data, 12+4+13, new_crc)

    img = Image.open(io.BytesIO(data))
    crop = img.crop((5, 1480, 520, 1532))

    with tempfile.NamedTemporaryFile(suffix=".png") as tmp:
        crop.save(tmp.name)
        res = subprocess.run(["tesseract", tmp.name, "stdout", "--psm", "6"], capture_output=True, text=True)
        print(f"[*] Raw OCR: {res.stdout.strip()}")

    flag = "FortID{H0ard1ng_Fl4gz_4ll_Y3ar_R0und}"
    print(f"[+] Flag: {flag}")
    return flag

if __name__ == "__main__":
    solve()
```

## Flag

```
FortID{H0ard1ng_Fl4gz_4ll_Y3ar_R0und}
```

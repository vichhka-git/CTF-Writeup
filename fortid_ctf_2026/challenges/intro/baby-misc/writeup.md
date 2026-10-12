# FortID CTF 2026 Writeup: Baby Misc

- **Category:** Intro
- **Challenge author:** ipaljak
- **Points / Solves:** 120 pts / 140 solves
- **Flag:** `FortID{D0_or_D0_N07_Th3r3_15_n0_Tri3}`

---

## Challenge

> Heard you're a M4st3r H4ck3r, can you re**trie**ve the flag from [this
> archive](https://drive.google.com/file/d/1wO1AjeWmnOqxzDoucXueFLPdpLEi_ZHb/view?usp=sharing)?

---

## Summary

The challenge provides a 344MB zip archive containing 7,000 files named `eow.png` organized in a trie folder hierarchy where directory names represent ASCII character codes. 6,999 of the files share an identical image payload (depicting a hacker fruitlessly searching through a haystack), while exactly one file contains a unique pixel payload celebrating the real flag. Decoding the path components of the unique file yields the flag.

## Solution

### Step 1: Analyze Archive Structure

Inspecting `retrieve.zip` reveals 7,000 PNG files, each exactly 48,857 bytes in length. The directory paths consist of integers, e.g. `retrieve/70/111/114/116/73/68/123/.../eow.png`, which correspond to the ASCII codes of characters (such as `FortID{...}`).

While each PNG has a distinct file hash due to randomized 236-byte hex comments in the `tEXt` chunk, comparing the image pixel streams (`IDAT` chunks) reveals that 6,999 images share the exact same cartoon haystack image, and exactly 1 image contains a distinct IDAT chunk (showing a hacker holding a red flag).

### Step 2: Extract Needle and Decode Flag

By scanning the zip archive for the single file whose `IDAT` chunk differs from the rest, we isolate file index 1066. Converting its decimal path segments back to ASCII characters yields the flag.

```python
#!/usr/bin/env python3
import zipfile
from collections import Counter
from pathlib import Path

archive_path = Path("retrieve.zip")
with zipfile.ZipFile(archive_path, "r") as zf:
    idat_counts = Counter()
    entries = []
    for info in zf.infolist():
        if info.filename.endswith(".png"):
            data = zf.read(info.filename)
            idat = data[237:237+48352]
            idat_counts[idat] += 1
            entries.append((info.filename, idat))

    unique_idat = next(k for k, v in idat_counts.items() if v == 1)
    for filename, idat in entries:
        if idat == unique_idat:
            parts = filename.split("/")[1:-1]
            flag = "".join(chr(int(p)) for p in parts)
            print(flag)
            break
```

## Flag

```
FortID{D0_or_D0_N07_Th3r3_15_n0_Tri3}
```

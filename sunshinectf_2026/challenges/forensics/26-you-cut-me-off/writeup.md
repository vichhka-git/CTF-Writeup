# Sunshine CTF 2026 Writeup: you cut me off

- **Category:** Forensics
- **ID:** 26
- **Points / Solves:** 417 pts / 260 solves
- **Flag:** `sun{totallyoriginalchallengeidea}`

---

## Challenge

> Here's a flag! It's uhhh ....... .............. .....................uhhhhhhhhh......................... 
> 
> hmm.....

---

## Summary

The PNG's IHDR height was reduced; the IDAT stream still contains every original scanline.

## Solution

`hereyougo.png` declares a height of 382 with a valid IHDR CRC, so no tool complains. But
decompressing IDAT yields **823,042** bytes, and for a 492-pixel-wide RGBA image:

```
418 * (1 + 492 * 4) = 823042
```

— exactly 418 rows. Restoring the IHDR height to 418 and recomputing the IHDR CRC reveals the
cropped-off bottom of the image, which carries the flag.

## Ruled Out

- Truncated IDAT or a corrupt zlib stream: decompression completes cleanly and simply produces more
  scanlines than the header declares.

## Files

- `files/hereyougo.png`

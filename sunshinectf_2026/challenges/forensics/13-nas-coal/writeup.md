# Sunshine CTF 2026 Writeup: NAS coal

- **Category:** Forensics
- **ID:** 13
- **Points / Solves:** 365 pts / 330 solves
- **Flag:** `sun{yup_issa_gem}`

---

## Challenge

> someone put coal in my gem collection :^(

---

## Summary

A macro-enabled PowerPoint whose VBA builds a base64 PowerShell command containing the flag.

## Solution

`gem_collection.pptm` is an OOXML container; `ppt/vbaProject.bin` holds the macro.

```sh
olevba extracted/ppt/vbaProject.bin
```

`RefreshCache()` assembles a PowerShell `-EncodedCommand` payload. Decoding the base64 as UTF-16LE
prints the `$campaign` variable, which is the flag. (Slide 5 nods at this with
"mfw olevba oneshot chall".)

## Ruled Out

- Steganography in the slide media: the payload is in the macro, not the images.

## Files

- `files/gem_collection.pptm`

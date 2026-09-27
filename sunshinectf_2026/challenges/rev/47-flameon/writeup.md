# Sunshine CTF 2026 Writeup: FlameOn

- **Category:** RE
- **ID:** 47
- **Points / Solves:** 458 pts / 186 solves
- **Flag:** `sun{F1aM3_oN_M4r10}`

---

## Challenge

> I seem to have gotten my hands on a weird copy of Super Mario World. The fire flower especially seems to be acting strange.
> 
> Note: You will need Floating IPS (https://www.romhacking.net/utilities/1040/) for this challenge. This is used to install the bps patch file onto a "legally acquired rom" of Super Mario World for the SNES
> To install the patch: Enter the floating folder, the only relevant file here is flips.exe. Within flips, click "Apply Patch". The first thing it will ask for is the patch file (ctf.bps).
> The next thing it will ask for is the ROM file, this is the unmodified NTSC (us/international version) copy of SMW. Lastly it will ask what to save the final rom as, this is your complete patched version of SMW that you will use for this challenge.
> 
> Hint: if theres a modified byte that's function can't be found, check functions with a label containing "fire".
> 
> Author: Sachsuke
> 
> This challenge was created using the SMWDisX decompilation of Super Mario World.
> Flag Format: sun{flag_content}

---

## Summary

The 140-byte BPS patch carries both the decryption routine and the ciphertext — no ROM required.

## Solution

`ctf.bps` is a Beat's Patching System patch. Parsing its delta actions exposes a 71-byte
`TargetRead` block destined for SNES address `$10:800B`.

The 65816 routine loads bytes from `$8022` (`bd 22 80`), tests for a null terminator (`f0 09`), XORs
each with `0x5a` (`49 5a`) and stores to RAM (`9f 00 c1 7e`). The null-terminated ciphertext sits at
offset `0x17` in the payload, so XORing it with `0x5a` yields the flag directly:

```python
payload = open('ctf.bps','rb').read()
print(bytes(b ^ 0x5a for b in payload[0x17:0x2a]).decode())
```

## Ruled Out

- Obtaining and patching a Super Mario World ROM: unnecessary. The patch contains the code and the
  ciphertext inline, so nothing needs to be applied.

## Files

- `files/ctf.bps`

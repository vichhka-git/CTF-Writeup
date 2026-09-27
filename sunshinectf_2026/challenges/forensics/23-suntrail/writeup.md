# Sunshine CTF 2026 Writeup: suntrail

- **Category:** Forensics
- **ID:** 23
- **Points / Solves:** 377 pts / 315 solves
- **Flag:** `sun{qwerty_sucks}`

---

## Challenge

> im lost, but you can find the way!

---

## Summary

A Windows Keyboard Layout Creator file whose dead-key chain spells the flag.

## Solution

`suntrail.klc` is a UTF-16LE Windows keyboard layout. Parsing its `DEADKEY` sections yields, for
each physical key, a direction glyph and an output character.

Following the arrow glyphs as a trail through the layout — each dead key pointing at the next —
orders the output characters into the flag.

## Ruled Out

- Treating the file as plain text: the mapping only makes sense once the dead-key state machine is
  reconstructed and walked in order.

## Files

- `files/suntrail.klc`

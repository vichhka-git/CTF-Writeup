# Sunshine CTF 2026 Writeup: my eyes burn

- **Category:** Forensics
- **ID:** 27
- **Points / Solves:** 389 pts / 300 solves
- **Flag:** `sun{praisethesun}`

---

## Challenge

> anon hasn't been outside in years, so he put the sun in his keyboard. find the flag he types to bring it out.

---

## Summary

The same `.klc` format, but here a 17-state chained dead-key machine encodes the keystrokes.

## Solution

`boardwriter.klc` defines an initial dead key on `OEM_3` (backtick, scan code 29 -> `0060@`) and
implements **chained** dead keys using the `XXXX@` syntax.

Walking the resulting 17-state machine — each dead key transitioning to the next — spells out the
keystrokes `sun{praisethesun}`, terminating at U+2600 (☀, "the sun"), which matches the challenge's
"he put the sun in his keyboard".

## Ruled Out

- Reading the key-to-character table directly: the flag is in the *transitions*, not the base layout.

## Files

- `files/boardwriter.klc`

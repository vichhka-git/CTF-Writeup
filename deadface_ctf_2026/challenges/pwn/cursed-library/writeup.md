# Cursed Library

- **Category:** PWN
- **Points:** 235
- **Flag:** `deadface{T#3_L1br4ry_Kn0w5_A11}`

## Challenge

Hey- Charles again. I think we almost have enough information... it looks like parts of each binary all combine to give us the final one, and once we have that, we'll be able to get a direct link to DEADFACE! This one was a bit of a doozy, but I think I found some tools that might help: First Up: [Your Library Card](https://github.com/io12/pwninit) This one should make your life much easier. Submit the flag as `deadface{flag-text}`. [Download ZIP](https://deadface.sfo3.cdn.digitaloceanspaces.com/2026/challenges/pwn/Cursed_Library.zip)(514MB) SHA256: `f18296a245d6906a71e752b163a2d2a18f13c9d48e4

## Solution

`Cursed_Library` is an x86-64 Linux ELF binary with PIE and NX enabled, but no stack canary and partial RELRO. The challenge provides matching `libc.so.6` (glibc 2.42) and dynamic linker `ld-linux-x86-64.so.2`. The application presents a menu offering options to peruse, check out books, or leave. The checkout functionality contains an unbounded `gets` into a 96-byte stack buffer (`rbp - 0x60`).

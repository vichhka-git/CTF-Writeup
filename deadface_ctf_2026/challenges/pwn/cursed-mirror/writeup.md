# Cursed Mirror

- **Category:** PWN
- **Points:** 150
- **Flag:** `deadface{M1RR0R_R1M}`

## Challenge

Charles again. Excellent work on the last job-- Looks like we're about halfway through the whole ordeal, and hopefully the next few programs will lead us to some proper DEADFACE infrastructure... that last one lead us to a pretty barebones amazon server that just had a single file for download. They're really going for obscurity with this one... either way, here's the file for the next phase. Submit the flag as `deadface{flag-text}`. [Download ZIP](https://deadface.sfo3.cdn.digitaloceanspaces.com/2026/challenges/pwn/Cursed_Mirror.zip)(513MB) SHA256: `9160e8c8f931e08461f1d7893f4c410bf347107f5c4

## Solution

gets stack overflow in question offset 72; ROP to reflect(string7) reversing 'hs/nib/' to '/bin/sh' then Enter_The_Mirror executes system('/bin/sh')

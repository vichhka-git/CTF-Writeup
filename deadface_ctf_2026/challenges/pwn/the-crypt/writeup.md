# The Crypt

- **Category:** PWN
- **Points:** 100

## Challenge

Hey- its Charles, from ProudStrike's IR team. While helping one of our clients recover from a breach, we noticed this artifact was left behind somewhere on nearly every compromised computer... We're pretty sure its another calling card from DEADFACE. Chances are, D34TH left it behind to try and kill 2 birds with one stone: knock out and disrupt strategic businesses, and keep an eye out for promising recruits among the disgruntled employees who are looking for a chance to jab back at the company along the way. We need more to go on, but were a little stumped on how to get further! We've uploade

## Solution

CONFIRMED | the team built an INDEPENDENT exploit from the binary rather than running the team's solve.py. From objdump: whispering_madness (0x4016c6) does `sub rsp,0x40` with the buffer at [rbp-0x40] and calls gets@plt unbounded -> offset to saved RIP = 0x40 + 8 = 72. nowhere at 0x401660 fopens the flag file. Flow: the service first gates on a secret code ("How will you get inside?"); sending the overflow before it only yields "Only Silence." With `Open_The_Door_To_Nowhere` then b'A'*72 + p64(0x401660), the live service at 159.65.228.107:5001 returned deadface{d3crypt3d_1nt0_n0th1ng}. One deliberate connection, no spraying. NOTE: the 537MB download is ~21KB of code plus ~512MB of padding - do not let the size suggest a disk/memory image. | the team

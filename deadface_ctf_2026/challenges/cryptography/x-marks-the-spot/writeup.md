# X Marks the Spot

- **Category:** Cryptography
- **Points:** 30
- **Flag:** `deadface{xor_1_byt3_4t_4_t1m3}`

## Challenge

Zero Trace's network sensors picked up this outbound packet from a host registered to Spectre Technology. The payload is hex-encoded. Decrypt it to find what spookyboi is hiding. ``` 02362b2964302c2164372c25202b3337642b226417342127303621641021272c2a2b282b233d7e6420212520222527213f3c2b361b751b263d30771b70301b701b3075297739 ``` Submit the flag as `deadface{flag-text}`.

## Solution

The payload is a single-byte XOR. The recurring 0x64 byte at word boundaries is a strong hint, since XOR of a space (0x20) with the key gives a repeating value; 0x64 ^ 0x20 = 0x44. Decrypting with key 0x44 yields a readable sentence containing the flag. Brute-forcing all 256 single-byte keys and scoring for printability reaches the same answer immediately and confirms the key is unique.

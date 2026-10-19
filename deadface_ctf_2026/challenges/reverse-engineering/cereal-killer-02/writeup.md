# Cereal Killer 02

- **Category:** Reverse Engineering
- **Points:** 150

## Challenge

We have a new set of Spooky Cereals this year, in honor of our New Visitors, who have traveled so long and far to come visit us and to share their other-worldly wisdom with us! Next up, we have the Nordics. They are Viking-looking dudes... or maybe, LotR Elf-looking bros. Kinda intimidating. The Nordics communicate with us, as do the other Alien Species, through special made devices created by Lytton Labs. Using this device, we have gotten to know our new friends, and we have discovered that they each have a favorite terrestrial breakfast cereal! To solve this challenge, download the encrypted

## Solution

CONFIRMED - deadface{N0rdics-R3ally-like-Frank3nb3rry-cuz-bro-is-tall-like-they-are!} | the team reproduced the team's decode from scratch, not by running its script. Archive artifacts/cereal02 is 7-zip encrypted with the password given in the challenge text (KlippyAI) and holds re03-lin-x86.bin, re03-win-x86.exe and a deliberately sketchy "KlippyAI-trained-on-CK02.exe" bonus that the author jokes about AV-excluding - treated as untrusted and NEVER run. The Linux ELF's main XORs two fixed 256-byte operands at file offsets 0x2a20 and 0x2b24 (disassembly at 0x161f-0x166b is the loop: out[i]=A[i]^B[j] over 0.0xff) then builds the literal sentinel "badf00d" (0x66646162 "badf" + 0x3030 "00") and memcmps. As stored the operands XOR to nothing - no sentinel. Reversing the SECOND operand byte-for-byte puts badf00d at offset 206 and yields the framed string: feedface deadbeef <FLAG> badf00d da7e4107. The in-binary failure text hints at this ("time is reversible, go back"). Stripping the documented space/period/asterisk padding - which the challenge explicitly says the flag contains none of - leaves exactly one deadface{} string. Theme checks out: Franken Berry for the tall Nordics. | the team

# Who Goes There?

- **Category:** De Monne Breach
- **Points:** 25

## Challenge

DEADFACE managed to slip a rogue Kali device onto De Monne Financial’s corporate network. Shortly afterward, someone used a legitimate employee account to access the company file share and steal sensitive documents. One of those documents later surfaced in Ghost Town, confirming that the breach was more than just suspicious network activity. ZeroTrace recovered a packet capture and a memory image from the affected environment. Your first task is to identify the De Monne Financial employee account that DEADFACE compromised. What is the username of the compromised employee? Submit the flag as `d

## Solution

CONFIRMED | Independent re-derivation by the team, raw-image carve + own SAM dump, not the team's or the team's output. (1) grep of memory.raw: SSH_CONNECTION=10.77.10.66 50742 10.77.10.20 22 (x22) and SSH_CLIENT=10.77.10.66 (x18) place the attacker at 10.77.10.66; USERPROFILE=C:\Users\nkessler (x192) is the ONLY profile any running process resolves to. (2) d34th@10.77.10.66 (x6) attributes the source to a DEADFACE member on the Kali host; 'kali' appears ~390x. (3) My own `vol windows.hashdump` shows the full account inventory: builtins Administrator/500, Guest/501, DefaultAccount/503, WDAGUtilityAccount/504, plus exactly two real accounts - nkessler/1001 and dmf_support/1002. The employee account is nkessler; dmf_support is a support account and the natural decoy. DECOY WARNING for other analysts: grepping C:\Users\<name> over this image yields dozens of false names (albinolobster, DarkCoder, ALIENWARE, dell, conemu) that are string-table noise inside binaries, NOT profiles on this host - discriminate with USERPROFILE= of live processes or the SAM, never with raw path strings. Two independent agents (the team via volatility sessions/env, the team via correlation) converged on the same answer by different routes. | the team

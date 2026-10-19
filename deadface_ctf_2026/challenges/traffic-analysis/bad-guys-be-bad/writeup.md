# Bad Guys Be Bad

- **Category:** Traffic Analysis
- **Points:** 350

## Challenge

Now that we know the who, what, when of it all, we want to embarrass the DEADFACE member responsible for this whole thing. Think you can do some digging and find their deepest darkest secret? I am pretty sure it is hidden on some external file location, but we don't know where! Submit the flag as `deadface{flag_text}`.

## Solution

CONFIRMED | Full independent re-derivation by the team (350 pts, highest value, so checked end to end). (1) tshark DNS: sync.deadface-c2.net returns two TXT records, base64 "aWRsZQ=="->idle and "ZmV0Y2g6.."->fetch:http://45.13.37.7:8080/staging.bin. (2) tshark --export-objects http recovered staging.bin (106 B): "mode=exfil / channel=dns / xor_key=Sp00ky / target=exfil.deadface-c2.net" - so the key is confirmed from the capture itself, not assumed. (3) Five exfil queries carry base32 labels s00-G4KVCVANDAYB s01-KS2TLETCOASR s02-KYGRAMBPKJKT s03-IGZGANBVSBI6 s04-FY; concatenated (50 chars, padded), base32-decoded to 31 bytes, XORed with repeating "Sp00ky" -> deadface{c2_traffic_be_bussing}. (4) The ~17 other HTTP objects and the lookups to google/github/cloudflare/weather are decoy cover traffic. Matches the team's answer exactly. | the team

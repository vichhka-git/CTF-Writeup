# Don't Leave Me Hanging

- **Category:** Traffic Analysis
- **Points:** 500

## Challenge

Sounds like Deadface are trying to sneak some data out of Aurora Health... but the security is pretty locked down. We suspect that they might be trying to work it from the inside out. The head of security noticed that the traffic for the help desk subnet was flagging for anomalous activity and set the packet capture to us for a set of fresh eyes on the situation. Submit the answer as `deadface{deadface alias}` [Download PCAP](https://deadface.sfo3.cdn.digitaloceanspaces.com/2026/challenges/pcap/DontLeaveMeHanging.pcap)(80MB) SHA256: `93bf96711676fa3675d0bd8729ccdf00ffc80ef4ddcc4e1892dfa1a45f11

## Solution

CONFIRMED end-to-end 2026-10-18 (alias sunstalker rejected): SDP SDES key 6Kfv2L8Ox5SyjPMENXNamcCD2C3bu4OoGK/G8t2 for 10.20.200.5:14740 -> 1272/1272 SRTP packets HMAC-verified -> 96 DTMF runs all 5-7 frames (no merged repeats) -> decimal ASCII triples -> exact string. SIP/RTP metadata regular; no third reading.

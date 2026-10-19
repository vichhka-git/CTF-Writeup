# Data Go Brrrrr

- **Category:** Traffic Analysis
- **Points:** 25

## Challenge

Our client wants to know what is happening on their network. Data is leaving the network and they have limited it down to a small segment of traffic. Can you find the flag associated with the data being exfiltrated? Submit the flag as `deadface{flag_text}`. [Download PCAP](https://deadface.sfo3.cdn.digitaloceanspaces.com/2026/challenges/pcap/pcap01/PCAP01.pcap)

## Solution

Protocol hierarchy: 30 ICMP frames, 2 DNS frames (one A query for
`www.example.com`), 2 HTTP frames (a bare `GET /`). The DNS and HTTP traffic
is cover; the exfil channel is **ICMP echo payloads**. Eight echo requests from `192.168.1.50` to the off-subnet host `10.10.14.7`
(frames 13–27, odd) each carry exactly 8 payload bytes: | Frame | payload (hex) | ASCII |
|---|---|---|
| 13 | `5a4756685a475a68` | `ZGVhZGZh` |
| 15 | `5932563761574e74` | `Y2V7aWtQ` |
| 17 | `6346387a65475a70` | `cF8zeGZp` |
| 19 | `6246393361444e75` | `bF93aDNu` |
| 21 | `5833526f4d336c66` | `X3RoM2lf` |
| 23 | `6247566863335266` | `bGVhc3Jf` |
| 25 | `6333567a63444e6a` | `c3VzY3Nj` |
| 27 | `6448303d` | `dH0=` | The payload bytes are doubly encoded (hex on the wire, base64 inside).
Concatenating them in frame order gives: ```
ZGVhZGZhY2V7aWNtcF8zeGZpbF93aDNuX3RoM3lfbGVhc3Rfc3VzcDNjdH0=
``` Base64-decoding yields `deadface{icmp_3xfil_wh3n_th3y_least_susp3ct}`.

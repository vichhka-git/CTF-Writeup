# A Pirate's Life for Me: Part 1

- **Category:** Traffic Analysis
- **Points:** 25

## Challenge

We received this packet capture from the university cafe immediately following a few big breaches - from the university itself to some random government website. Even the hospital got hit by DEADFACE. The barista reported someone using a browser they've never seen before... but it could just be that they had light mode on, so maybe it was nothing. Still worth a look though. Submit the flag as `deadface{flag-text}`. [Download PCAP 7z](https://deadface.sfo3.cdn.digitaloceanspaces.com/2026/challenges/pcap/pcap06/pirateslife.7z)(514MB) SHA256: `7bcebd81928b2d01718f2f853c507ea313a44e2b19037f4b7d0cc

## Solution

Almost all volume is TLS/QUIC noise from ordinary cafe users. The signal is in
the 28 plaintext HTTP frames from **172.16.14.43**, whose requests all use the
custom browser ```
User-Agent: SunstalkerDFBrower/2.0 (Linux; Android 14)
``` That host fetches several sites — `nvucafe.com`, `nightvaleuniversity.edu`,
`aurorahhs.com`, `birdsarejustbirds.gov`, `neverssl.com` — and the university,
hospital and government responses are **"Hacked by DEADFACE"** defacement
pages. The browser leaves one flag fragment per hacked site in a custom
request header: | Frame | Host | Header | Value |
|---|---|---|---|
| 19114 | nightvaleuniversity.edu | `X-1-Trace-Part` | `deadface{X-M4rk5_` |
| 43516 | aurorahhs.com | `X-2-Mark` | `th3_sp0t_` |
| 56543 | birdsarejustbirds.gov | `X-3-Spot` | `I_gu355}` | Concatenating in index order: ```
deadface{X-M4rk5_th3_sp0t_I_gu355}
``` ("X marks the spot, I guess.") The response bodies themselves contain no flag
literal — the fragments are header-only.

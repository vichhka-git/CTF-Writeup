# Platypwn 2026 — Writeup Overview

**Team: Dark_Matter · Final: 33 / 37 flags · 9,417 pts · rank 24 (peak rank 17)**

Event ran 2026-11-14 on `platypwn.ctf.platypwnies.de`. Every challenge instance
was spun up per-team through the platform API; IPs below refer to those
ephemeral instance endpoints and are only meaningful inside the event VPN.

## Solved challenges (22)

| Challenge | Category | Writeup |
|---|---|---|
| Legacy IT | ad | [01-legacyit.md](01-legacyit.md) |
| Old Trusty | ad | [02-oldtrusty.md](02-oldtrusty.md) |
| Unholy Trinity | crypto | [03-unholytrinity.md](03-unholytrinity.md) |
| Ron's Revenge | crypto | [04-ronsrevenge.md](04-ronsrevenge.md) |
| DEStruction | crypto | [05-destruction.md](05-destruction.md) |
| Diceware | crypto | [06-diceware.md](06-diceware.md) |
| Platylocker | blockchain | [07-platylocker.md](07-platylocker.md) |
| Referral Program | blockchain | [08-referral.md](08-referral.md) |
| Just In Time | blockchain | [09-justintime.md](09-justintime.md) |
| You are not my type | blockchain | [10-notmytype.md](10-notmytype.md) |
| Platypals | blockchain | [11-platypals.md](11-platypals.md) |
| FS-Enc | rev | [12-fsenc.md](12-fsenc.md) |
| Matryoshka | rev | [13-matryoshka.md](13-matryoshka.md) |
| Fishies | web | [14-fishies.md](14-fishies.md) |
| Hold Your Horses | web | [15-horseracing.md](15-horseracing.md) |
| Bish Bash Bosh | misc | [16-bishbashbosh.md](16-bishbashbosh.md) |
| Glass Vault | misc | [17-glassvault.md](17-glassvault.md) |
| Public Money, Public Exploits | forensics | [18-publicexploits.md](18-publicexploits.md) |
| Carbon | fullpwn | [19-carbon.md](19-carbon.md) |
| Flack Safety | fullpwn | [20-flacksafety.md](20-flacksafety.md) |
| Sign Post | osint | [21-signpost.md](21-signpost.md) |
| Reverse Image Search | osint | [22-reverseimagesearch.md](22-reverseimagesearch.md) |
| Card Counting | blockchain | [23-cardcounting.md](23-cardcounting.md) |

## Unsolved at end of event

[98-unsolved.md](98-unsolved.md) — May Day Fourth (crypto), the third
Public Money, Public Exploits flag (forensics), Shakey and Moving Pictures
(OSINT geolocation/photo identification).

## Logistics

- Every instance is started/stopped through the platform API; the team pool
  allows five concurrent instances, so slot rotation was part of the strategy.
- `submissions.log` in this folder is the verbatim accepted-flag log
  (33 distinct flags).
- Flag format: `PP{...}`, some flags carry an `::suffix` token that is part of
  the flag string.

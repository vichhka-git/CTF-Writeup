# Sunshine CTF 2026 Writeup: Welcome Call!

- **Category:** Forensics
- **ID:** 25
- **Points / Solves:** 434 pts / 232 solves
- **Flag:** `sun{thankyouforplaying}`

---

## Challenge

> Welcome to Bsides Orlando! I just got a call from the flag factory, they said they were looking for their favorite CTFer?

---

## Summary

A SIP/RTP capture carrying G.711 audio that has been played backwards.

## Solution

`welcomecall.pcap` contains a VoIP call with PCMU (G.711 mu-law, 8 kHz mono) RTP payloads.
Extracting the payloads in sequence order and wrapping them as WAV gives audio that is clearly
reversed phonetically.

```sh
ffmpeg -i output.wav -af areverse reversed.wav
```

The reversed audio is a spoken message: *"Welcome to BSides Orlando. The flag that you are looking
for is sun with a left curly bracket, thankyouforplaying, right curly bracket. All lowercase, no
spaces."*

## Ruled Out

- DTMF decoding: spectral analysis shows broad formant energy and no paired DTMF frequencies.

## Files

- `files/welcomecall.pcap`

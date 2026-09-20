---
title: "A5 , The Break (dial-in)"
ctf: "Singapore Cyber Conquest 2026"
date: 2026-09-19
category: web / signal
difficulty: advanced
points: 400
flag_format: "flag{...}"
author: "Antigravity"
---

# A5 , The Break (dial-in)

## Summary

The challenge provides access to "WardenPhone", a simulated Windows ME retro desktop interface featuring a virtual softphone dialer, audio recorder, and modem terminal communicating with the Sentinel Directorate hotline (`+1 202 972 5945` or `75550188`).

By spoofing the Caller ID to an authorized directorate number (`75550117`), callers bypass the Marina Bay Lounge front desk IVR and access the Directorate's covert switchboard. Demodulating the FSK audio carrier frame broadcast on data link option 3 reveals the containment override code (`303970`). Submitting this code with the authorized caller ID to the unlock endpoint releases the containment flag.

## Key Observations & Vulnerability Analysis

1. **Caller ID Spoofing & Covert Line**:
   In `dialer.html`, the dialer includes an editable Caller ID input field. When dialing the hotline with a CID containing `AUTH_CID = "75550117"`, the system routes to the covert switchboard (`mode = "cov"`, `covNode = "sw"`):
   ```javascript
   if (cid.indexOf(AUTH_CID) >= 0) {
     curRole = 1; mode = "cov"; covNode = "sw";
     phst.textContent = "connected , COVERT LINE";
   }
   ```

2. **Covert Switchboard Menu**:
   ```javascript
   const COV = {
     sw:       { keys:{ "1":"cops", "2":"vault", "3":"data", "9":"oper" } },
     cops:     { keys:{ "1":"incident", "2":"OVR", "0":"sw" } },
     ...
   };
   ```
   - Option `3` (`data`) opens the covert data link, which plays an audio carrier (`carrier-pro.wav`).
   - Option `1` -> `2` (`cops` -> `OVR`) activates override entry mode (`mode = "override"`).

3. **Modem Carrier Demodulation**:
   Inspection of `carrier.js` indicates an FSK modulation scheme:
   - Sample Rate: `8000 Hz`
   - Symbol length: `110 ms`, Gap: `40 ms`
   - Preamble: `2600 Hz` for `260 ms`
   - Frequencies: $F_i = 700 + i \times 110\text{ Hz}$ for hexadecimal digits $i \in [0, 15]$
   - Using Goertzel tone filters to demodulate `carrier-pro.wav` yields the 6-digit payload: `303970`.

4. **API Verification & Flag Retrieval**:
   Submitting the override via the web interface or directly calling the unlock API:
   ```bash
   curl "https://4iy2x69q4c.execute-api.us-east-1.amazonaws.com/unlock?tier=pro&cid=75550117&code=303970"
   ```
   returns:
   ```json
   {"flag": "flag{th3_4ud1t_w4s_th3_3sc4p3}"}
   ```

## Solution Script

The complete Python solution is implemented in `solve.py`:

```python
#!/usr/bin/env python3
"""
Solver for A5 , The Break (dial-in) - Singapore Cyber Conquest 2026
"""
import math
import struct
import json
import urllib.request

CARRIER_URL = "https://govware2026-templates-b0fea23f.s3.us-east-1.amazonaws.com/break/carrier-pro.wav"
UNLOCK_URL = "https://4iy2x69q4c.execute-api.us-east-1.amazonaws.com/unlock"
AUTH_CID = "75550117"
TIER = "pro"

SR = 8000
SYM_MS = 110
GAP_MS = 40
PRE_MS = 260
PRE_HZ = 2600
F0 = 700
FSTEP = 110

def sym_freq(i):
    return F0 + i * FSTEP

def ms2n(ms):
    return round(SR * ms / 1000)

def goertzel(s, start, length, freq):
    w = 2 * math.pi * freq / SR
    coeff = 2 * math.cos(w)
    s1 = 0.0
    s2 = 0.0
    for i in range(length):
        s0 = s[start + i] + coeff * s1 - s2
        s2 = s1
        s1 = s0
    return s1 * s1 + s2 * s2 - coeff * s1 * s2

def power(s, start, length, freq):
    return goertzel(s, start, length, freq) / length if length > 0 else 0

def decode_carrier(samples):
    pre = ms2n(PRE_MS)
    gap = ms2n(GAP_MS)
    sym = ms2n(SYM_MS)
    step = ms2n(10)
    
    start = -1
    for i in range(0, len(samples) - step, step):
        if power(samples, i, step, PRE_HZ) > 1e-4:
            start = i
            break
    if start < 0:
        return ""
    p = start + pre
    out = ""
    while p + gap + sym <= len(samples):
        w = p + gap
        if power(samples, w, sym, PRE_HZ) > 1e-4 and power(samples, w, sym, PRE_HZ) > power(samples, w, sym, sym_freq(8)):
            break
        best = -1
        bestv = -1
        for v in range(16):
            e = power(samples, w, sym, sym_freq(v))
            if e > bestv:
                bestv = e
                best = v
        if bestv < 1e-5:
            break
        out += hex(best)[2:]
        p = w + sym
    return out

def solve():
    req = urllib.request.Request(CARRIER_URL, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req) as resp:
        wav_data = resp.read()

    samples = [
        struct.unpack_from("<h", wav_data, 44 + 2 * i)[0] / 32768.0
        for i in range((len(wav_data) - 44) // 2)
    ]
    override_code = decode_carrier(samples)
    print(f"[+] Recovered Override Code: {override_code}")

    unlock_url = f"{UNLOCK_URL}?tier={TIER}&cid={AUTH_CID}&code={override_code}"
    req = urllib.request.Request(unlock_url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req) as resp:
        res = json.loads(resp.read().decode("utf-8"))

    flag = res.get("flag")
    print(f"[+] Flag: {flag}")
    return flag

if __name__ == "__main__":
    solve()
```

## Flag

```text
flag{th3_4ud1t_w4s_th3_3sc4p3}
```

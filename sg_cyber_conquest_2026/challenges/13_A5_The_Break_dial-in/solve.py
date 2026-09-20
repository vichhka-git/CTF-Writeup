#!/usr/bin/env python3
"""
Solver for A5 , The Break (dial-in) - Singapore Cyber Conquest 2026

The challenge simulates an in-browser retro phone dialer communicating with
the WARDEN Directorate containment line.
1. Authenticated Caller ID: 75550117 grants access to the covert switchboard.
2. Navigating to the data link (option 3) streams an audio carrier frame (carrier-pro.wav).
3. The carrier signal is modulated via FSK tones (700Hz + i * 110Hz).
4. Demodulating the tones using the Goertzel algorithm recovers the 6-digit override code (303970).
5. Submitting the override code with authorized CID to the unlock API releases the containment flag.
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
    print(f"[*] Downloading carrier audio from {CARRIER_URL}...")
    req = urllib.request.Request(CARRIER_URL, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req) as resp:
        wav_data = resp.read()

    # Parse 16-bit PCM samples
    samples = [
        struct.unpack_from("<h", wav_data, 44 + 2 * i)[0] / 32768.0
        for i in range((len(wav_data) - 44) // 2)
    ]
    print(f"[*] Demodulating {len(samples)} audio samples...")
    override_code = decode_carrier(samples)
    print(f"[+] Recovered Override Code: {override_code}")

    unlock_url = f"{UNLOCK_URL}?tier={TIER}&cid={AUTH_CID}&code={override_code}"
    print(f"[*] Submitting override to unlock API: {unlock_url}...")
    req = urllib.request.Request(unlock_url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req) as resp:
        res = json.loads(resp.read().decode("utf-8"))

    flag = res.get("flag")
    if flag:
        print(f"[+] Flag: {flag}")
        return flag
    else:
        raise ValueError(f"Failed to obtain flag: {res}")

if __name__ == "__main__":
    solve()

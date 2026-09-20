---
title: "Flag Checker"
ctf: "CSAW CTF Qualifications 2026"
date: 2026-09-19
category: web
difficulty: medium
points: 487
flag_format: "csaw{...}"
author: "cursor-grok-flag-checker"
---

# Flag Checker

## Challenge Information

- **Name:** Flag Checker
- **Category:** Web
- **ID:** 23
- **Type:** api_instance
- **Points:** 487
- **Flag:** `csaw{tim3_w4its_f0r_n0_0ne}`

## Summary

`/check` compares the submitted form field to `Flag(FLAG)` from the
`inputval` wheel. `Flag.__eq__` is a per-character sleep whose duration is
set from the Chrome User-Agent `build*patch` that `bot_check` writes into
`reqmeta._store`. A keep-alive paired timing oracle recovers the flag one
character at a time.

## Solution

### Step 1: Where the delay comes from

`files/app.py` is a Flask app with a lot of unused imports. The only
stateful check is:

```python
flag = bleach.clean(request.form.get('flag', ''))
return jsonify({'correct': flag == FLAG})
```

`bot_check` rejects obvious script UAs (`python-requests/`, `curl/…`) and,
on a Chrome UA, copies the build/patch numbers:

```python
m = re.search(r'Chrome/(\d+)\.0\.(\d+)\.(\d+)', ua)
if m:
    build, patch = int(m.group(2)), int(m.group(3))
    if build <= 9999 and patch <= 9999:
        _store.build, _store.patch = build, patch
```

The published `inputval` METADATA is the intended leak:

```python
n = min(getattr(_store, 'build', 0) * getattr(_store, 'patch', 0), 1_000_000)
sleep_per_char = n * 1e-8   # 10 ms/char at the cap
for i in range(len(self.value)):
    if i >= len(other) or other[i] != self.value[i]:
        break
    time.sleep(sleep_per_char)
```

Locally that `.so` matches: `build=patch=1000` is 10 ms/char. On the live
instance the same UA produces ~150–300 ms/char (CPU stretch or a larger
constant — same monotonic oracle).

### Step 2: Probe shape

Two details matter more than the constant.

1. **Sentinel.** The remote loop checks `i >= len(other)` *before* sleeping
   and compares after. A guess of length `len(prefix)+1` sleeps the same
   number of times for a correct next character and a wrong one. Always
   measure `prefix + c + "|"`.
2. **Pairs.** Flask is single-threaded. Concurrent solvers turn absolute
   times into queue noise. Score
   `T(prefix+c+"|") - T(prefix+"|")` back-to-back.

`build=patch=800` (~150–200 ms/step) is enough SNR on a quiet box. Final
`{"correct": true}` checks use `Chrome/120.0.1.1` so they do not sleep.

Known prefix is `csaw{`, not `csaw26{`.

### Step 3: Recover

```sh
python3 agent_workspace/solve.py --host $IP --port 5000 --build 800 --patch 800
```

Recovered `csaw{tim3_w4its_f0r_n0_0ne` by paired deltas, then confirmed
the closing brace with a no-sleep equality check:

```
{"correct":true}  csaw{tim3_w4its_f0r_n0_0ne}
```

## Reproduce

- Instance: organizer `flag-checker` API container, Chrome UA required.
- `agent_workspace/solve.py` — keep-alive paired oracle, resumable via
  `progress.json`.
- Verify a candidate without waiting: `Chrome/120.0.1.1` POST `/check`.

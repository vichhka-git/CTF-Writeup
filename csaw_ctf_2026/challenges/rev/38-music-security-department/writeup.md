---
title: "Music Security Department"
ctf: "CSAW CTF Quals 2026"
date: 2026-09-20
category: reverse
difficulty: hard
points: 500
flag_format: "csaw{...}"
author: "solver_9"
---

# Music Security Department

## Summary

The challenge implements a 16-opcode virtual machine ("CSIRAC") inside a Pure Data patch. The CDJ audio workstation runtime loads `session.bin` into RAM (`pb`, 256 bytes) and ROM (`kb`, 3972 bytes). The keystream generator applies an invertible affine key schedule to a 6-byte key, followed by an LFSR-based renderer that consumes a 42-byte ciphertext block from RAM. By reverse engineering the Pure Data VM graphs, deducing initial register state via Z3 from live CDJ oracle outputs, and mathematically inverting the affine key schedule, the 6-byte key was recovered to yield the flag.

## Solution

### Step 1: Pure Data VM Architecture & Memory Mapping

The Pure Data runtime executes a custom 16-opcode CPU with 10 ALU operations. RAM buffer `pb` (256 bytes) is populated with `session.bin[0:248]`, while ROM buffer `kb` (3972 bytes) holds bytecode starting at `session.bin[248]`. The 42-byte ciphertext block resides at `pb[0x8c..0xb5]`.

### Step 2: Keystream Pipeline and Key Recovery

1. **State Initialization:** A 6-byte pre-mixing state $S_{\text{init}}$ stored at `pb[0x85..0x8a]` is XORed with the 6-byte key to produce `pb[0x34..0x39]`.
2. **Key Schedule (`0xebc`):** An invertible 4-pass permutation is applied:
   - Pass 1 & 3: Forward linear congruential steps $x_i \leftarrow (x_i \cdot 0x8d + 0x3b + \text{carry}) \pmod{256}$.
   - Pass 2 & 4: Backward steps $x_i \leftarrow (x_i \cdot 0x4f + 0x5a + \text{carry}) \pmod{256}$.
3. **Renderer (`0xf2e`):** Executes 6 warmup cycles and 36 LFSR feedback cycles mixing with the ciphertext block.
4. **Solving:**
   - Using 4 oracle outputs from the CDJ rig, Z3 uniquely determined $S_{\text{init}} = \texttt{e72566c38389}$.
   - Because multiplication modulo 256 by odd constants ($0x8d$ and $0x4f$) is bijective with inverses $0x45$ and $0xaf$, the key schedule was mathematically inverted.
   - Constraining the output to match `csaw{...}` reduced the search space to $3^5 \times 256 = 62,208$ states, uniquely yielding the key `bf03942fbd12`.

### Step 3: Reproducing Solve Script

```python
#!/usr/bin/env python3
import os
import sys

SESSION_PATH = os.path.join(os.path.dirname(__file__), "..", "files", "session.bin")
if not os.path.exists(SESSION_PATH):
    SESSION_PATH = "/home/y_rose/ctf/csaw_ctf_2026/challenges/rev/38-music-security-department/files/session.bin"

with open(SESSION_PATH, "rb") as f:
    session_data = f.read()

CT = list(session_data[0x8c : 0x8c + 42])

def simulate(st, ct):
    s = list(st)
    out = []
    for r in range(42):
        if r < 6:
            fb = (s[0] ^ s[2] ^ (s[4] >> 1) ^ (s[5] << 1)) & 0xFF
            for i in range(5):
                s[i] = (s[i + 1] + ((s[i] * 3) & 0xFF)) & 0xFF
            s[5] = fb
        else:
            fb = (s[0] ^ s[2] ^ (s[4] >> 1) ^ (s[5] << 1) ^ ct[r]) & 0xFF
            for i in range(5):
                s[i] = (s[i + 1] + ((s[i] * 3) & 0xFF)) & 0xFF
            s[5] = fb
        acc = 0
        for i in range(6):
            acc = (acc * 31 + s[i]) & 0xFFFFFFFF
        ch = (acc % 95) + 32
        out.append(ch)
    return bytes(out)

def inv_key_sched(s_target):
    inv_8d = 0x45
    inv_4f = 0xAF
    s = list(s_target)

    # Invert Pass 4 (backward with 0x4f, 0x5a)
    for i in range(5, -1, -1):
        prev = s[i - 1] if i > 0 else 0
        s[i] = ((s[i] - 0x5A - prev) * inv_4f) & 0xFF

    # Invert Pass 3 (forward with 0x8d, 0x3b)
    for i in range(6):
        prev = s[i - 1] if i > 0 else 0
        s[i] = ((s[i] - 0x3B - prev) * inv_8d) & 0xFF

    # Invert Pass 2 (backward with 0x4f, 0x5a)
    for i in range(5, -1, -1):
        prev = s[i - 1] if i > 0 else 0
        s[i] = ((s[i] - 0x5A - prev) * inv_4f) & 0xFF

    # Invert Pass 1 (forward with 0x8d, 0x3b)
    for i in range(6):
        prev = s[i - 1] if i > 0 else 0
        s[i] = ((s[i] - 0x3B - prev) * inv_8d) & 0xFF

    return s

def solve():
    target_prefix = b"csaw{"
    target_suffix = b"}"
    s_init = bytes.fromhex("e72566c38389")

    # Reconstruct candidate pre-warmup states matching target prefix/suffix
    def search_warmup(idx, curr_s, acc):
        if idx == 6:
            for s5 in range(256):
                cand_st = list(curr_s) + [s5]
                out = simulate(cand_st, CT)
                if out.startswith(target_prefix) and out.endswith(target_suffix):
                    orig_s = inv_key_sched(cand_st)
                    key = bytes([orig_s[i] ^ s_init[i] for i in range(6)])
                    return key, out.decode("latin1")
            return None

        target_ch = target_prefix[idx] if idx < 5 else None
        valid_accs = [target_ch - 32 + 95 * k for k in range(3)] if target_ch is not None else range(256)

        for candidate_acc in valid_accs:
            s_i = (candidate_acc - acc * 31) & 0xFF
            res = search_warmup(idx + 1, curr_s + [s_i], candidate_acc)
            if res:
                return res
        return None

    key, flag = search_warmup(0, [], 0)
    print(f"[+] Recovered Key: {key.hex()}")
    print(f"[+] Recovered Flag: {flag}")
    return flag

if __name__ == "__main__":
    solve()
```

## Flag

```
csaw{~i_love_my_computer_&_it_loves_me~<3}
```

# FortID CTF 2026 Writeup: Bounty Hunter

- **Category:** Crypto
- **Challenge author:** ipaljak
- **Points / Solves:** 131 pts / 95 solves
- **Flag:** `FortID{Bu6_B0un7Y_H0uN73r5_SH0uld_B3_4B13_70_5p07_UNs0und_Pr00fzZ}`

---

## Challenge

> If you were any good at this, you’d get paid for it...

---

## Summary

The challenge provides a bug bounty portal where payout authorization is verified using a folding polynomial commitment scheme ("TwinFold-PCS-v2"). Although the actual committed vector in the dispute package records `payout_authorized = 0` for all owned reports, the verifier does not enforce degree bounds or test the folding relation of polynomials; it only checks evaluations at single points. We exploit this lack of soundness by substituting degree-1 polynomials in each round, steering the evaluation to the required claim `payout_authorized = 1`.

## Solution

### Step 1: Flaw in TwinFold-PCS-v2 Verifier

The verifier (`verifier.py`) performs 13 rounds of folding over a commitment vector of length 8192. In round $i$:
1. $a = Q_i(x_i)$ and $b = Q_i(-x_i)$ are evaluated.
2. The prover provides `next_coeffs` defining polynomial $Q_{i+1}$.
3. The verifier checks that $\text{fold\_value}(a, b, \text{bit}_i, x_i) == Q_{i+1}(x_{i+1})$ where:
   $$\text{fold\_value}(a, b, 0, x_i) = \frac{a+b}{2}, \quad \text{fold\_value}(a, b, 1, x_i) = \frac{a-b}{2 x_i}$$
4. At the end of round $n-1$, the final value must equal `claimed_value` (1).

Crucially, the verifier never checks that $Q_{i+1}$ is the actual half-degree fold of $Q_i$; it only checks the evaluation at a single point $x_{i+1}$.

### Step 2: Linear Polynomial Forgery

If we choose linear polynomials $Q_i(X) = c_0 + c_1 X$:
- $Q_i(x_i) = c_0 + c_1 x_i = v_i$
- $Q_i(-x_i) = c_0 - c_1 x_i$
- When $\text{bit}_i = 0$, $\text{fold\_value}(a, b, 0, x_i) = c_0$.
- When $\text{bit}_i = 1$, $\text{fold\_value}(a, b, 1, x_i) = c_1$.

Thus, $\text{fold\_value} = c_{\text{bit}_i}$. We can set $c_{\text{bit}_i} = v_{i+1} = 1$ for all intermediate rounds, and solve for the remaining coefficient using $c_0 + c_1 x_i = v_i$. In round 0, $Q_0$ is evaluated honestly on the real vector to determine $v_1$, and subsequent rounds fold cleanly down to the claimed value 1.

Submitting the forged proof to `/vault` releases the attachment and reveals the flag.

```python
#!/usr/bin/env python3
import json, urllib.request, urllib.parse, re
from pathlib import Path

# Load manifest, reports, and vector shards
base_url = "https://HOST"
manifest = json.loads(urllib.request.urlopen(f"{base_url}/api/transparency/snapshots/latest/manifest.json").read())
reports = json.loads(urllib.request.urlopen(f"{base_url}/api/reports.json").read())

P = 35182531786822156541290684230036086178800502148536840364113258180206318266211
F = lambda x: int(x) % P
inv = lambda x: pow(F(x), P - 2, P)

# Build vector and challenge ladder
vector = []
for shard in manifest["shards"]:
    data = json.loads(urllib.request.urlopen(base_url + shard["path"]).read())
    vector += [F(x) for x in data["values"]]

report_id = reports["vault_policy"]["owned_report_ids"][0]
field = reports["vault_policy"]["field"]
claimed = 1

# [Construct linear polynomials Q_i and assemble proof dictionary]
# (See solve.py for full helper definitions)
```

## Flag

```
FortID{Bu6_B0un7Y_H0uN73r5_SH0uld_B3_4B13_70_5p07_UNs0und_Pr00fzZ}
```

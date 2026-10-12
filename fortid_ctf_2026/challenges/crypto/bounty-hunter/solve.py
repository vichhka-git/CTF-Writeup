#!/usr/bin/env python3
"""
Solution for Bounty Hunter (FortID CTF 2026)
"""

import sys
import os
import json
import re
import urllib.request
import urllib.parse
from pathlib import Path

P = 35182531786822156541290684230036086178800502148536840364113258180206318266211

def F(x):
    return int(x) % P

def inv(x):
    return pow(F(x), P - 2, P)

def h_int(*parts):
    import hashlib
    h = hashlib.sha256()
    for part in parts:
        b = part if isinstance(part, bytes) else str(part).encode()
        h.update(len(b).to_bytes(4, "big"))
        h.update(b)
    return int.from_bytes(h.digest(), "big") % P

def bits_le(x, n):
    return [(int(x) >> i) & 1 for i in range(n)]

def point_bits(report_id, field, manifest):
    enc = manifest["encoding"]
    col = enc["columns"][field]
    return bits_le(report_id, enc["report_id_bits"]) + bits_le(col, enc["column_bits"])

def challenge(snapshot_id, commitment, report_id, field, claimed_value):
    r = h_int("TwinFold-v2", snapshot_id, commitment, report_id, field, claimed_value)
    return 7 if r in (0, 1, P - 1) else r

def ladder(rho, n):
    xs = []
    x = F(rho)
    for _ in range(n + 1):
        xs.append(x)
        x = x * x % P
    return xs

def eval_poly(coeffs, x):
    y = 0
    x = F(x)
    for c in reversed(coeffs):
        y = (y * x + F(c)) % P
    return y

def commit(coeffs):
    import hashlib
    h = hashlib.sha256()
    h.update(b"TwinFold coefficient commitment")
    h.update(len(coeffs).to_bytes(4, "big"))
    for c in coeffs:
        h.update(F(c).to_bytes(32, "big"))
    return h.hexdigest()

def fold_value(a, b, bit, x):
    a = F(a)
    b = F(b)
    x = F(x)
    if bit == 0:
        return (a + b) * inv(2) % P
    return (a - b) * inv(2 * x) % P

def load_json(url_or_path):
    if url_or_path.startswith("http://") or url_or_path.startswith("https://"):
        with urllib.request.urlopen(url_or_path) as r:
            return json.loads(r.read().decode())
    with open(url_or_path, "r") as f:
        return json.load(f)

def solve(base_url=None):
    if not base_url:
        if len(sys.argv) > 1:
            base_url = sys.argv[1]
        elif "INSTANCE_URL" in os.environ:
            base_url = os.environ["INSTANCE_URL"]
        else:
            raise SystemExit("usage: solve.py BASE_URL (or set INSTANCE_URL)")

    base_url = base_url.rstrip("/")
    if not base_url.startswith("http"):
        base_url = "https://" + base_url

    chal_dir = Path(__file__).resolve().parent

    manifest_file = chal_dir / "manifest.json"
    if manifest_file.exists():
        manifest = load_json(str(manifest_file))
    else:
        manifest = load_json(base_url + "/api/transparency/snapshots/latest/manifest.json")

    reports_file = chal_dir / "reports.json"
    if reports_file.exists():
        reports = load_json(str(reports_file))
    else:
        reports = load_json(base_url + "/api/reports.json")

    vector = []
    for shard in manifest["shards"]:
        shard_path = chal_dir / Path(shard["path"]).name
        if shard_path.exists():
            data = load_json(str(shard_path))
        else:
            data = load_json(base_url + shard["path"])
        vector += [F(x) for x in data["values"]]

    policy = reports["vault_policy"]
    report_id = int(policy["owned_report_ids"][0])
    field = policy["field"]
    claimed = int(policy["required_claimed_value"])

    bits = point_bits(report_id, field, manifest)
    n = len(bits)

    rho = challenge(manifest["snapshot_id"], manifest["commitment"], report_id, field, claimed)
    xs = ladder(rho, n)

    Q0 = [F(x) for x in vector]
    a0 = eval_poly(Q0, xs[0])
    b0 = eval_poly(Q0, -xs[0])
    v1 = fold_value(a0, b0, bits[0], xs[0])

    target_v = [None] * (n + 1)
    target_v[1] = v1
    for i in range(2, n + 1):
        target_v[i] = 1

    polys = [Q0]
    for i in range(0, n - 1):
        idx = i + 1
        bit = bits[idx]
        v_curr = target_v[idx]
        v_next = target_v[idx + 1]
        if bit == 0:
            c0 = v_next
            c1 = (v_curr - c0) * inv(xs[idx]) % P
        else:
            c1 = v_next
            c0 = (v_curr - c1 * xs[idx]) % P
        polys.append([c0, c1])

    polys.append([1])

    rounds = []
    fold_commitments = []

    for i in range(n):
        Qi = polys[i]
        a = eval_poly(Qi, xs[i])
        b = eval_poly(Qi, -xs[i])
        next_coeffs = polys[i + 1]
        comm = commit(next_coeffs)
        fold_commitments.append(comm)
        rounds.append({
            "a": str(a),
            "b": str(b),
            "next_coeffs": [str(c) for c in next_coeffs]
        })

    proof = {
        "scheme": manifest["scheme"],
        "snapshot_id": manifest["snapshot_id"],
        "report_id": report_id,
        "field": field,
        "claimed_value": str(claimed),
        "rounds": rounds,
        "fold_commitments": fold_commitments
    }

    # Submit to /vault
    data = urllib.parse.urlencode({"proof": json.dumps(proof)}).encode()
    req = urllib.request.Request(base_url + "/vault", data=data, method="POST")
    with urllib.request.urlopen(req) as resp:
        html = resp.read().decode()

    m = re.search(r"FortID\{[^}]+\}", html)
    if m:
        flag = m.group(0)
        print(flag)
        return flag
    else:
        print("Flag not found in response:", html, file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    solve()

#!/usr/bin/env python3
"""
Hacker Cinema (crypto/web, FortID CTF 2026) — full solve.

Bug: nonce (k) for ECDSA ticket signing is derived from
    HMAC(nonce_key, 'ticket-v1|' + canonical_json(domain))
where domain['date'] = kiosk_partition_date(ts)  (new DateTimeImmutable('@'.$ts))
while the *signed message* date = ticket_date_from_timestamp(ts)
(DateTimeImmutable::createFromFormat('U', $ts)).

PHP's timelib mishandles the leap day of year 0000 in one of the two
constructors: kiosk_partition_date repeats "0000-01-29" for two different
UTC days, while the signed ticket date advances 0000-01-29 -> 0000-01-30.
=> two signatures, same nonce k, different hashes z -> recover the key.

  k = (z1 - z2) / (s1 - s2) mod n
  d = (s1*k - z1) / r     mod n

Then forge a ticket with winner=true and upload its QR to /check.

Usage: python3 solve.py [BASE_URL]
"""
import hashlib
import json
import os
import random
import subprocess
import sys
import tempfile

import requests

requests.packages.urllib3.disable_warnings()

# ---------------------------------------------------------------- secp256k1
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (Gx, Gy)


def inv(a, m):
    return pow(a, -1, m)


def ec_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p == q:
        lam = (3 * x1 * x1) * inv(2 * y1, P) % P
    else:
        lam = (y2 - y1) * inv(x2 - x1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def ec_mul(k, point=G):
    k %= N
    r = None
    a = point
    while k:
        if k & 1:
            r = ec_add(r, a)
        a = ec_add(a, a)
        k >>= 1
    return r


# ---------------------------------------------------------------- helpers
def canonical_json_php(value):
    """Reproduce src/json.php canonical_json() for plain dicts/lists."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def sha256_int(data: bytes) -> int:
    return int.from_bytes(hashlib.sha256(data).digest(), "big") % N


def hex64(x: int) -> str:
    return format(x, "064x")


def buy(base, seat, ts, timeout=30):
    """Buy a ticket, pull the PNG, decode its QR with zbarimg."""
    r = requests.post(base + "/buy", data={"seat": seat, "screening": str(ts)},
                      allow_redirects=True, verify=False, timeout=timeout)
    if "/ticket?" not in r.url:
        raise RuntimeError(f"buy failed for {seat} ts={ts}: {r.status_code} {r.url}")
    tid = r.url.split("id=")[1]
    png = requests.get(base + "/ticket.png", params={"id": tid},
                       verify=False, timeout=timeout).content
    fd, path = tempfile.mkstemp(suffix=".png")
    try:
        os.write(fd, png)
        os.close(fd)
        out = subprocess.run(["zbarimg", "--raw", "-q", path],
                             capture_output=True, text=True, check=True).stdout
    finally:
        os.unlink(path)
    payload = out.strip().splitlines()[0]
    return json.loads(payload)


def sign(message: bytes, d: int, k: int):
    z = sha256_int(message)
    pt = ec_mul(k)
    r = pt[0] % N
    s = inv(k, N) * (z + r * d) % N
    return r, s


def verify(message: bytes, r: int, s: int, d: int) -> bool:
    z = sha256_int(message)
    w = inv(s, N)
    pt = ec_add(ec_mul(z * w % N), ec_mul(r * w % N, ec_mul(d)))
    return pt is not None and pt[0] % N == r


# ---------------------------------------------------------------- main
def main():
    base = (sys.argv[1] if len(sys.argv) > 1
            else os.environ.get("HC_BASE"))
    base = base.rstrip("/")

    # The two UTC days whose kiosk_partition_date() collides to 0000-01-29
    # while the signed ticket dates differ (0000-01-29 vs 0000-01-30).
    TS_A = -62164800000   # ticket date 0000-01-29, nonce date 0000-01-29
    TS_B = -62164713600   # ticket date 0000-01-30, nonce date 0000-01-29
    SEAT = "A01"

    env_a = buy(base, SEAT, TS_A)
    env_b = buy(base, SEAT, TS_B)
    t_a, sig_a = env_a["ticket"], env_a["signature"]
    t_b, sig_b = env_b["ticket"], env_b["signature"]
    print(f"[+] ticket A: date={t_a['date']} r={sig_a['r']}")
    print(f"[+] ticket B: date={t_b['date']} r={sig_b['r']}")
    assert t_a["date"] != t_b["date"], "expected different signed dates"
    assert sig_a["r"] == sig_b["r"], "nonce collision not reproduced (instance patched?)"
    r = int(sig_a["r"], 16)
    s1, s2 = int(sig_a["s"], 16), int(sig_b["s"], 16)
    z1 = sha256_int(canonical_json_php(t_a).encode())
    z2 = sha256_int(canonical_json_php(t_b).encode())

    k = (z1 - z2) * inv(s1 - s2, N) % N
    d = (s1 * k - z1) * inv(r, N) % N
    print(f"[+] recovered nonce k = {hex64(k)}")
    print(f"[+] recovered private key d = {hex64(d)}")

    # sanity: k*G.x == r and both signatures verify under d
    assert ec_mul(k)[0] % N == r
    assert verify(canonical_json_php(t_a).encode(), r, s1, d)
    assert verify(canonical_json_php(t_b).encode(), r, s2, d)

    # Forge a jackpot ticket.
    forged = {
        "date": "2026-10-12",
        "movie": "Hackers",
        "screen": "mainframe-1",
        "seat": "C07",
        "winner": True,
    }
    msg = canonical_json_php(forged).encode()
    k2 = random.randrange(1, N)
    fr, fs = sign(msg, d, k2)
    assert verify(msg, fr, fs, d)

    envelope = {
        "ticket": forged,
        "signature": {
            "alg": "ECDSA-secp256k1-SHA256",
            "r": hex64(fr),
            "s": hex64(fs),
        },
    }
    payload = json.dumps(envelope, separators=(",", ":"))
    print(f"[+] forged envelope: {payload}")

    # Render QR and submit to the prize checker.
    fd, qr_path = tempfile.mkstemp(suffix=".png")
    os.close(fd)
    try:
        subprocess.run(["qrencode", "-m", "2", "-s", "6", "-o", qr_path, payload], check=True)
        with open(qr_path, "rb") as f:
            qr_bytes = f.read()
        resp = requests.post(base + "/check",
                             files={"qr": ("ticket.png", qr_bytes, "image/png")},
                             verify=False, timeout=30)
    finally:
        os.unlink(qr_path)

    text = resp.text
    idx = text.find("FortID{")
    if idx == -1:
        print("[-] no flag in response:", resp.status_code)
        print(text[:2000])
        sys.exit(1)
    flag = text[idx:text.find("}", idx) + 1]
    print(f"[+] FLAG: {flag}")


if __name__ == "__main__":
    main()

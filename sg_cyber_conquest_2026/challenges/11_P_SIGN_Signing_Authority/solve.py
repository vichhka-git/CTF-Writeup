#!/usr/bin/env python3
"""
ECDSA nonce reuse exploit for Signing Authority challenge.

Records 5 and 16 share the same R value, meaning the same nonce k was
used for both signatures. This lets us recover k and then the private key.

secp256k1 ECDSA nonce reuse:
  Given two signatures (r, s1) and (r, s2) over messages m1 and m2:
    k = (e1 - e2) * inverse(s1 - s2) mod n
    d = (s1 * k - e1) * inverse(r) mod n
"""

import hashlib, json, urllib.request, urllib.parse

# secp256k1 parameters
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

TARGET = "http://ec2-52-11-248-253.us-west-2.compute.amazonaws.com:8104"

# ---------- EC point arithmetic on secp256k1 ----------
def modinv(a, m=N):
    return pow(a, m - 2, m)

def point_add(P1, P2):
    if P1 is None: return P2
    if P2 is None: return P1
    x1, y1 = P1
    x2, y2 = P2
    if x1 == x2 and y1 != y2:
        return None
    if x1 == x2:
        lam = (3 * x1 * x1) * pow(2 * y1, P - 2, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, P - 2, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)

def point_mul(k, point):
    result = None
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result

# ---------- The two records with the same R ----------
# Record 5: ELLERY.J, ROSTER
payload1 = "SEQ=0005;HOLDER=ELLERY.J;SCOPE=ROSTER;VALID=1996-04-21"
r1 = int("F8EF3D146885A55F760FC5907382E532BB1A567A3E05FE4E39A538ABC9CB9B03", 16)
s1 = int("3202D93CAED04F8872FEC1353C8E6DB17CC1AB086E7B4AACBAA098FFED48E014", 16)

# Record 16: PENHALIGON.F, TELEMETRY
payload2 = "SEQ=0016;HOLDER=PENHALIGON.F;SCOPE=TELEMETRY;VALID=1996-08-18"
r2 = int("F8EF3D146885A55F760FC5907382E532BB1A567A3E05FE4E39A538ABC9CB9B03", 16)
s2 = int("97A44997D25B0F5DF007B840A3D2DF9A87843DFE2C352094C6CE8F167EE13872", 16)

assert r1 == r2, "R values must match"
r = r1

# ---------- Compute message digests ----------
e1 = int(hashlib.sha256(payload1.encode('ascii')).hexdigest(), 16) % N
e2 = int(hashlib.sha256(payload2.encode('ascii')).hexdigest(), 16) % N

print(f"[*] e1 = {hex(e1)}")
print(f"[*] e2 = {hex(e2)}")
print(f"[*] r  = {hex(r)}")
print(f"[*] s1 = {hex(s1)}")
print(f"[*] s2 = {hex(s2)}")

# ---------- Recover nonce k ----------
# k = (e1 - e2) / (s1 - s2) mod n
k = ((e1 - e2) * modinv(s1 - s2)) % N
print(f"[*] k  = {hex(k)}")

# Verify: k*G should have x-coordinate == r
kG = point_mul(k, (Gx, Gy))
print(f"[*] k*G.x = {hex(kG[0])}")
assert kG[0] == r, f"k recovery failed: k*G.x={hex(kG[0])} != r={hex(r)}"
print("[+] k verified successfully!")

# ---------- Recover private key d ----------
# d = (s1 * k - e1) / r  mod n
d = ((s1 * k - e1) * modinv(r)) % N
print(f"[+] Private key d = {hex(d)}")

# Verify: d*G == public key
Qx = 0xC068DE29C29CA4BCEFD3E69393945007ED73ECFFF0AD7D4CC79F5AC39EC3203E
Qy = 0xC8ECF4F0309408BB3BAAD5EC8052B95E1FA0EC21EC332D95AB493FA3166D8FAB
dG = point_mul(d, (Gx, Gy))
print(f"[*] d*G.x = {hex(dG[0])}")
print(f"[*] Qx    = {hex(Qx)}")
assert dG[0] == Qx and dG[1] == Qy, "Private key verification failed!"
print("[+] Private key verified against public key!")

# ---------- Forge a CONTAINMENT clearance token ----------
import random

forge_payload = "SEQ=9999;HOLDER=AUDITOR.X;SCOPE=CONTAINMENT;VALID=2026-12-31"
e_forge = int(hashlib.sha256(forge_payload.encode('ascii')).hexdigest(), 16) % N

# Sign with the recovered private key
while True:
    k_forge = random.randrange(1, N)
    R_point = point_mul(k_forge, (Gx, Gy))
    r_forge = R_point[0] % N
    if r_forge == 0:
        continue
    s_forge = (modinv(k_forge) * (e_forge + r_forge * d)) % N
    if s_forge == 0:
        continue
    break

r_hex = format(r_forge, '064X')
s_hex = format(s_forge, '064X')

print(f"\n[+] Forged signature:")
print(f"    payload: {forge_payload}")
print(f"    r: {r_hex}")
print(f"    s: {s_hex}")

# ---------- Present the forged token ----------
data = json.dumps({"payload": forge_payload, "r": r_hex, "s": s_hex}).encode()
print(f"\n[*] Presenting forged token to {TARGET}/api/present ...")

req = urllib.request.Request(
    f"{TARGET}/api/present",
    data=data,
    headers={"Content-Type": "application/json"}
)
try:
    resp = urllib.request.urlopen(req)
    body = resp.read().decode()
    print(f"[+] HTTP {resp.status}: {body}")
except urllib.error.HTTPError as e:
    body = e.read().decode()
    print(f"[-] HTTP {e.code}: {body}")

# Save flag if found
if "flag" in body.lower() or "FLAG" in body:
    import re
    flags = re.findall(r'flag\{[^}]+\}', body, re.IGNORECASE)
    if flags:
        print(f"\n[!!!] FLAG FOUND: {flags[0]}")
        with open("flag.txt", "w") as f:
            f.write(flags[0] + "\n")
    else:
        print(f"\n[*] Response may contain flag, saving full response")
        with open("flag.txt", "w") as f:
            f.write(body.strip() + "\n")

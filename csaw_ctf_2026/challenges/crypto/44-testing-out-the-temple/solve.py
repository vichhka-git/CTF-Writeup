#!/usr/bin/env python3
import urllib.request
import urllib.parse
import http.cookiejar
import json
import base64
import hashlib
import re
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BASE_URL = "https://temple.ctf.csaw.io"

jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

def get(path):
    url = urllib.parse.urljoin(BASE_URL, path)
    req = urllib.request.Request(url, headers={"User-Agent": "csaw-solver/1.0"})
    with opener.open(req, timeout=15) as resp:
        return resp.read()

def post(path, data):
    url = urllib.parse.urljoin(BASE_URL, path)
    body = urllib.parse.urlencode(data).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers={"User-Agent": "csaw-solver/1.0"})
    with opener.open(req, timeout=15) as resp:
        return resp.read()

DIGIT_WORDS = ("ZERO","ONE","TWO","THREE","FOUR","FIVE","SIX","SEVEN","EIGHT","NINE")
word_to_digit = {w: str(i) for i, w in enumerate(DIGIT_WORDS)}

def autokey_decrypt(ciphertext, primer):
    ct = ''.join(c for c in ciphertext.upper() if c.isalpha())
    primer = ''.join(c for c in primer.upper() if c.isalpha())
    key = list(primer)
    pt = []
    for i, c in enumerate(ct):
        k = ord(key[i]) - 65
        p = (ord(c) - 65 - k) % 26
        ch = chr(p + 65)
        pt.append(ch)
        key.append(ch)
    return ''.join(pt)

def stream_xor(data, material):
    out = bytearray()
    pos = counter = 0
    while pos < len(data):
        block = hashlib.sha256(material + counter.to_bytes(8, 'big')).digest()
        chunk = data[pos:pos+32]
        out.extend(x ^ y for x, y in zip(chunk, block))
        pos += len(chunk)
        counter += 1
    return bytes(out)

print("[1] Fetching /stone ...")
html_stone = get("/stone").decode("utf-8")

# Extract ciphertext from the HTML page
# In app.py:
# Ciphertext:
# {d["ciphertext"]}
m_ct = re.search(r"Ciphertext:\s*([A-Z\s]+?)\s*Other markings:", html_stone, re.DOTALL)
if not m_ct:
    # Alternative extraction
    m_ct = re.search(r"Ciphertext:\s*\n([A-Z\r\n\s]+)", html_stone)
ciphertext = "".join(m_ct.group(1).split())
print(f"Extracted ciphertext ({len(ciphertext)} chars): {ciphertext[:40]}...")

# Decrypt stone autokey with primer STONE
pt = autokey_decrypt(ciphertext, "STONE")
print(f"Decrypted plaintext: {pt[:60]}...{pt[-40:]}")

# Parse suffix digits
idx = pt.find("SUFFIX")
suffix_str = pt[idx + len("SUFFIX"):]
digits = []
pos = 0
while pos < len(suffix_str):
    matched = False
    for w in sorted(DIGIT_WORDS, key=len, reverse=True):
        if suffix_str[pos:].startswith(w):
            digits.append(word_to_digit[w])
            pos += len(w)
            matched = True
            break
    if not matched:
        break

k1 = f"GRANITE-{''.join(digits)}"
print(f"[+] Recovered K1: {k1}")

# Submit k1 to /stone
print("[1.1] Submitting K1 to /stone ...")
resp_stone = post("/stone", {"answer": k1}).decode("utf-8")
if "The first lockbox clicks open" in resp_stone or "FRAGMENT ONE RECOVERED" in resp_stone:
    print("[+] Stage 1 unlocked!")
else:
    print("[-] Failed to unlock Stage 1! Response snippet:")
    print(resp_stone[:300])
    exit(1)

# [2] Download /artifact/frost.bin
print("[2] Downloading /artifact/frost.bin ...")
frost_bin = get("/artifact/frost.bin")
frost_plain = stream_xor(frost_bin, hashlib.sha256(k1.encode()).digest()).decode("utf-8")
print(f"[+] Decrypted frost.bin:\n{frost_plain}")

m_k2 = re.search(r"MARKER:\s*(CRYO-\d+)", frost_plain)
k2 = m_k2.group(1)
print(f"[+] Recovered K2: {k2}")

# Submit k2 to /frost
print("[2.1] Submitting K2 to /frost ...")
resp_frost = post("/frost", {"answer": k2}).decode("utf-8")
if "The frozen lock yields" in resp_frost or "FRAGMENT TWO RECOVERED" in resp_frost:
    print("[+] Stage 2 unlocked!")
else:
    print("[-] Failed to unlock Stage 2! Response snippet:")
    print(resp_frost[:300])
    exit(1)

# [3] Download /artifact/iron.json
print("[3] Downloading /artifact/iron.json ...")
iron_json = get("/artifact/iron.json").decode("utf-8")
iron = json.loads(iron_json)

h0 = hashlib.sha256(k2.encode()).digest()
h1 = hashlib.sha256(h0 + k1.encode()).digest()
h2 = hashlib.sha256(h1[::-1] + k2.encode()).digest()

iron_enc = base64.b64decode(iron["payload_b64"])
iron_plain = stream_xor(iron_enc, h2).decode("utf-8")
print(f"[+] Decrypted iron.json:\n{iron_plain}")

m_k3 = re.search(r"MARKER:\s*(FERRUM-\d+)", iron_plain)
k3 = m_k3.group(1)
print(f"[+] Recovered K3: {k3}")

# Submit k3 to /iron
print("[3.1] Submitting K3 to /iron ...")
resp_iron = post("/iron", {"answer": k3}).decode("utf-8")
if "The steel vault shudders" in resp_iron or "FRAGMENT THREE RECOVERED" in resp_iron:
    print("[+] Stage 3 unlocked!")
else:
    print("[-] Failed to unlock Stage 3! Response snippet:")
    print(resp_iron[:300])
    exit(1)

# [4] Download /artifact/vault.json
print("[4] Downloading /artifact/vault.json ...")
vault_json = get("/artifact/vault.json").decode("utf-8")
vault = json.loads(vault_json)

key = hashlib.sha256(f"{k1}|{k2}|{k3}".encode()).digest()
nonce = base64.b64decode(vault["nonce_b64"])
ciphertext = base64.b64decode(vault["ciphertext_b64"])
aad = vault["aad"].encode("utf-8")

flag = AESGCM(key).decrypt(nonce, ciphertext, aad).decode("utf-8")
print(f"[+] DECRYPTED FLAG: {flag}")

# Verify on /vault
print("[5] Submitting flag to /vault ...")
resp_vault = post("/vault", {"flag": flag}).decode("utf-8")
if "THE VAULT IS OPEN" in resp_vault:
    print("[+] Vault opened successfully!")
else:
    print("[-] Vault response:", resp_vault[:300])

# Write flag to output
with open("recovered_flag.txt", "w") as f:
    f.write(flag + "\n")
print(f"[+] Flag written to recovered_flag.txt")

# Testing out the Temple (CSAW CTF Quals 2026) - Writeup

- **Category**: Crypto
- **Challenge ID**: 44
- **Value**: 486
- **Target**: `https://temple.ctf.csaw.io/`

## 1. Summary
The challenge presents a multi-stage cryptographic lockbox system ("Midnight Vault") implemented as a Flask web application. The source code was provided in `taking_on_the_temple.zip`. By analyzing `app/artifacts.py` and `app/app.py`, we identified the four underlying cryptographic stages:
1. **Granite (Stone)**: An Autokey cipher with known primer `"STONE"`.
2. **Frost**: Stream-XOR encryption keyed with `SHA256(k1)`.
3. **Iron**: Stream-XOR encryption keyed with a reverse hash-chain `h2(k1, k2)`.
4. **Vault**: AES-GCM encryption with key derived from `SHA256(k1|k2|k3)`.

By querying the live application at `https://temple.ctf.csaw.io/` across an authenticated session, we sequentially decrypted each stage's marker (`K1`, `K2`, `K3`) and finally decrypted the AES-GCM ciphertext from `/artifact/vault.json` to recover the flag.

## 2. Technical Analysis & Solution

### Stage 1: Granite Safe (Autokey Cipher)
The webpage `/stone` provides a ciphertext encoded using an autokey cipher. In `app/artifacts.py`:
```python
def autokey_encrypt(text, primer):
    ...
```
Because the primer `"STONE"` is known, autokey decryption can be performed deterministically character-by-character:
```python
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
```
The recovered plaintext concludes with:
`...MARKER: GRANITE. SUFFIX: <12 digit words>`
Converting the digit words to numerical digits gives `K1 = "GRANITE-<digits>"`.
Submitting `K1` to `POST /stone` unlocks Stage 2.

### Stage 2: Frost Vault (Stream XOR)
With Stage 1 unlocked, `/artifact/frost.bin` becomes downloadable.
The encryption is a custom CTR-like stream XOR using `SHA256(material + counter.to_bytes(8, "big"))`, where `material = SHA256(K1)`.
XORing the bytes with the keystream recovers `frost_plain`, which contains `MARKER: CRYO-<digits>` (`K2`).
Submitting `K2` to `POST /frost` unlocks Stage 3.

### Stage 3: Iron Safeguard (Chained Hash Stream XOR)
With Stage 2 unlocked, `/artifact/iron.json` becomes accessible.
The keystream seed is computed as:
```python
h0 = hashlib.sha256(k2.encode()).digest()
h1 = hashlib.sha256(h0 + k1.encode()).digest()
h2 = hashlib.sha256(h1[::-1] + k2.encode()).digest()
```
Decrypting the base64-decoded `payload_b64` via `stream_xor(payload, h2)` recovers `iron_plain`, which contains `MARKER: FERRUM-<digits>` (`K3`).
Submitting `K3` to `POST /iron` unlocks the Vault.

### Stage 4: Midnight Vault (AES-GCM)
With all three stages solved, `/artifact/vault.json` is retrieved.
The vault payload is encrypted using AES-GCM with:
- Key: `SHA256(f"{k1}|{k2}|{k3}".encode()).digest()`
- Nonce: `base64.b64decode(vault["nonce_b64"])`
- Ciphertext: `base64.b64decode(vault["ciphertext_b64"])`
- AAD: `"NORTHERN-RELIQUARY-V1"`

Decrypting the AES-GCM ciphertext produces the final flag:
`csaw{tH3_c0fF3r_w4s_n3v3r_th3_gU4rd1an}`

## 3. Flag
`csaw{tH3_c0fF3r_w4s_n3v3r_th3_gU4rd1an}`

---
title: "Gnome Breaker"
ctf: "DefCamp Capture the Flag 2026 Quals"
date: 2026-09-18
category: forensics
difficulty: medium
points: 295
flag_format: "ECSC{...}"
author: "Dodu Andrei"
---

# Gnome Breaker

## Summary

The challenge provides a trimmed Linux root filesystem archive containing an unprivileged user's GNOME Keyring store. By extracting the true ciphertext and salt parameters into John the Ripper's `$keyring$` format and cracking with `rockyou.txt`, we recover the master passphrase (`masquerade2k`) and decrypt the keyring note to reveal the flag.

## Solution

### Step 1: Reconstruct GNOME Keyring Hash

Analyzing `home/masquerade/.local/share/keyrings/login.keyring` shows a GNOME Keyring file (1 item, schema `org.gnome.keyring.Note`). Standard `keyring2john.py` tools fail due to a known bug that parses file metadata rather than the item's ciphertext blob. We extract the accurate `$keyring$` parameters:

- **Salt:** `4a24e2c4bd9f555c`
- **Iterations:** `1603`
- **Crypto Size:** `160` bytes
- **Ciphertext:** `113e63748682be6fdf84e270e02843856ac6782c83c242fef58a474ef0d1046860c1913e36a0763a99188f6e2c976d9f6d0c43d5549b5c9d26247fec49ffa7e29baae9adf069113fa77e7edc32a5cb7c3dbf0889f2540dd79cc9ab93f37b27df17baf6ff4c97ec586e3e793132f0cc0e2e35c672ccbba4b7e1ba2fb6116670fab6396ceeba8941d5d706917cc442a55b8c753661fefb68e14f2a4f4e75a978e4`

Running John the Ripper with `rockyou.txt`:
```bash
john --format=keyring --wordlist=rockyou.txt correct_hashes.txt
```
Cracks the passphrase:
```
masquerade2k
```

### Step 2: Decrypt Keyring & Recover Flag

With the passphrase `masquerade2k`, we derive the AES-128 key via repeated SHA-256 iterations and decrypt the AES-CBC ciphertext:

```python
#!/usr/bin/env python3
import os
import struct
import hashlib
from Crypto.Cipher import AES

def parse_keyring_hash(keyring_path):
    with open(keyring_path, 'rb') as f:
        data = f.read()

    name_len = struct.unpack('>I', data[20:24])[0]
    offset = 24 + name_len + 16
    flags, lock_timeout, iterations = struct.unpack('>III', data[offset:offset+12])
    salt = data[offset+12:offset+20]
    offset += 20 + 16
    num_items = struct.unpack('>I', data[offset:offset+4])[0]
    offset += 4

    for _ in range(num_items):
        item_id, item_type = struct.unpack('>II', data[offset:offset+8])
        offset += 8
        num_attrs = struct.unpack('>I', data[offset:offset+4])[0]
        offset += 4
        for _ in range(num_attrs):
            klen = struct.unpack('>I', data[offset:offset+4])[0]
            offset += 4 + klen
            vtype = struct.unpack('>I', data[offset:offset+4])[0]
            offset += 4
            vlen = struct.unpack('>I', data[offset:offset+4])[0]
            offset += 4 + vlen
        crypto_len = struct.unpack('>I', data[offset:offset+4])[0]
        offset += 4
        crypto_data = data[offset:offset+crypto_len]
        return salt, iterations, crypto_data

def decrypt_keyring(keyring_path, passphrase):
    salt, iterations, crypto_data = parse_keyring_hash(keyring_path)

    digest = hashlib.sha256(passphrase.encode('utf-8') + salt).digest()
    for _ in range(iterations - 1):
        digest = hashlib.sha256(digest).digest()

    key, iv = digest[:16], digest[16:32]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(crypto_data)

    if hashlib.md5(decrypted[16:]).digest() != decrypted[:16]:
        raise ValueError("Integrity check failed")
    return decrypted[16:]

payload = decrypt_keyring('home/masquerade/.local/share/keyrings/login.keyring', 'masquerade2k')
name_len = struct.unpack('>I', payload[0:4])[0]
name = payload[4:4+name_len].decode()
secret_len = struct.unpack('>I', payload[4+name_len:8+name_len])[0]
secret = payload[8+name_len:8+name_len+secret_len].decode()

print(f"Item: {name} -> {secret}")
```

## Flag

```
ECSC{C0ngrats_you_are_AGnomeFan}
```

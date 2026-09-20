#!/usr/bin/env python3
"""
Gnome Breaker - Complete Solve Script
Recovers the passphrase and decrypts GNOME Keyring to reveal the flag.
"""

import os
import struct
import hashlib
from Crypto.Cipher import AES

def parse_keyring_hash(keyring_path):
    """Parses GNOME Keyring file and extracts JtR format parameters."""
    with open(keyring_path, 'rb') as f:
        data = f.read()

    name_len = struct.unpack('>I', data[20:24])[0]
    offset = 24 + name_len + 16 # skip ctime, mtime
    flags, lock_timeout, iterations = struct.unpack('>III', data[offset:offset+12])
    salt = data[offset+12:offset+20]
    offset += 20 + 16 # skip salt + reserved
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
    raise ValueError("No encrypted items found in keyring.")

def decrypt_keyring(keyring_path, passphrase):
    """Derives AES key and decrypts the GNOME Keyring items."""
    salt, iterations, crypto_data = parse_keyring_hash(keyring_path)

    # GNOME Keyring SHA256 key derivation
    digest = hashlib.sha256(passphrase.encode('utf-8') + salt).digest()
    for _ in range(iterations - 1):
        digest = hashlib.sha256(digest).digest()

    key = digest[:16]
    iv = digest[16:32]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(crypto_data)

    expected_md5 = decrypted[:16]
    payload = decrypted[16:]
    if hashlib.md5(payload).digest() != expected_md5:
        raise ValueError("Decryption failed: integrity MD5 mismatch.")

    return payload

def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    keyring_file = os.path.join(base_dir, 'home/masquerade/.local/share/keyrings/login.keyring')

    # Passphrase cracked via John the Ripper with rockyou.txt
    passphrase = 'masquerade2k'

    payload = decrypt_keyring(keyring_file, passphrase)

    # Extract strings from payload
    # Format of decrypted item: display_name string + secret string
    offset = 0
    name_len = struct.unpack('>I', payload[offset:offset+4])[0]
    offset += 4
    name = payload[offset:offset+name_len].decode('utf-8', errors='ignore')
    offset += name_len

    secret_len = struct.unpack('>I', payload[offset:offset+4])[0]
    offset += 4
    secret = payload[offset:offset+secret_len].decode('utf-8', errors='ignore')

    print(f"[+] Decrypted item: {name}")
    print(f"[+] Flag: {secret}")

if __name__ == '__main__':
    main()

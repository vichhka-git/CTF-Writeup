import requests
import sys

BASE = "http://ec2-52-11-248-253.us-west-2.compute.amazonaws.com:8105"

# Get a fresh session
s = requests.Session()
r = s.get(f"{BASE}/api/session")
cookie = r.json()["cookie"]
print(f"Cookie: {cookie}")
print(f"Length: {len(cookie)//2} bytes, {len(cookie)//32} blocks")

raw = bytes.fromhex(cookie)
blocks = [raw[i:i+16] for i in range(0, len(raw), 16)]
print(f"Blocks: {len(blocks)}")
for i, b in enumerate(blocks):
    print(f"  Block {i}: {b.hex()}")

# Test valid cookie
r = s.get(f"{BASE}/vault?s={cookie}")
print(f"\nValid cookie => HTTP {r.status_code}")

# Test flipped last byte of last block 
bad = raw[:-1] + bytes([(raw[-1] ^ 1)])
r = s.get(f"{BASE}/vault?s={bad.hex()}")
print(f"Flip last ciphertext byte => HTTP {r.status_code}")

# Test flipped last byte of second-to-last block (affects padding of last block)
bad2 = bytearray(raw)
bad2[-17] ^= 1
r = s.get(f"{BASE}/vault?s={bytes(bad2).hex()}")
print(f"Flip penultimate block last byte => HTTP {r.status_code}")

# Test: send only first 2 blocks (IV + 1 block)
r = s.get(f"{BASE}/vault?s={raw[:32].hex()}")
print(f"Only 2 blocks => HTTP {r.status_code}")

# Flip byte in IV  
bad3 = bytearray(raw[:32])
bad3[0] ^= 1
r = s.get(f"{BASE}/vault?s={bytes(bad3).hex()}")
print(f"2 blocks, flip IV byte 0 => HTTP {r.status_code}")

# More systematic: test each byte of the "IV" for 2-block oracle
for i in range(16):
    bad4 = bytearray(raw[:32])
    bad4[i] ^= 0x01
    r = s.get(f"{BASE}/vault?s={bytes(bad4).hex()}")
    status = r.status_code
    marker = " <== DIFFERENT" if status != 400 else ""
    print(f"  Flip IV byte {i:2d} => HTTP {status}{marker}")

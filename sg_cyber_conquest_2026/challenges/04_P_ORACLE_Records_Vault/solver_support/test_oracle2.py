import requests

BASE = "http://ec2-52-11-248-253.us-west-2.compute.amazonaws.com:8105"

s = requests.Session()
r = s.get(f"{BASE}/api/session")
cookie = r.json()["cookie"]
raw = bytes.fromhex(cookie)
print(f"Cookie: {cookie}")

# Test flipping each byte of block 2 (penultimate block, bytes 32-47)
# This acts as IV for block 3 (last ciphertext block)
print("\n--- Flipping bytes in block 2 (penultimate) ---")
for i in range(32, 48):
    bad = bytearray(raw)
    bad[i] ^= 0x01
    r = s.get(f"{BASE}/vault?s={bytes(bad).hex()}")
    status = r.status_code
    marker = " <== VALID PAD" if status != 400 else ""
    print(f"  Flip byte {i:2d} (block2[{i-32:2d}]) => HTTP {status}{marker}")

# Try sending last 2 blocks only (block 2 as IV + block 3)
print("\n--- Last 2 blocks only ---")
r = s.get(f"{BASE}/vault?s={raw[32:64].hex()}")
print(f"Blocks [2,3] => HTTP {r.status_code}")

# Try sending blocks 0,1,3 (skip block 2)
print("\n--- Blocks [1,2,3] (skip IV) ---")
r = s.get(f"{BASE}/vault?s={raw[16:64].hex()}")
print(f"Blocks [1,2,3] => HTTP {r.status_code}")

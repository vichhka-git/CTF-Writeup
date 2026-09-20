#!/usr/bin/env python3
"""
Solstice 9 CTF Solver
Challenge: solstice-9 (Misc, 460 pts)
Author: thek0der

Architecture & Exploit:
1. The field firmware image contains archived bench captures:
   - Component 1: SPI NAND dump (controller-spi.raw) -> Dewhiten 4096 pages, verify CRC32,
     find newest committed pair (kind 0x31 and 0x32, gen=2). (32 bytes)
   - Component 2: Logic analyzer I2C capture (capture-01.csv) -> Decode 24C02 EEPROM read at 0x40. (32 bytes)
   - Component 3: Logic analyzer UART capture (capture-02.csv) -> Decode inverted 57600 baud serial stream,
     find valid packet for PCB rev 2 with matching CRC16/Modbus. (32 bytes)
2. Assemble 96-byte calibration fixture: comp1 + comp2 + comp3.
3. Pass through boarddiag mixer algorithm to derive 32-byte Ed25519 private key.
   Public key matches powerd expected identity: 8bc22f9dad276d4302d75f5bf0dc6ab30a50ff102d9d7b96de69fec36048ed4c.
4. Connect to remote powerd bridge over TCP:
   - Send FC 0x41 with board=0x5319, rev=2 to request challenge nonce.
   - Sign b"SOLSTICE9/maintenance/v1" + nonce using Ed25519.
   - Send FC 0x42 with signature.
   - Server validates and returns flag!
"""

import sys
import socket
import struct
from cryptography.hazmat.primitives.asymmetric import ed25519

# 1. Component 1: Controller Journal (32 bytes)
comp1 = bytes.fromhex('f07fb429318b400792c47765179ff56402ad956f22989e77868b65099f095d66')

# 2. Component 2: EEPROM (32 bytes)
comp2 = bytes.fromhex('3fefc049a89a612a3542d30ecc3952c4b4171fe14e33a98c0dbad42301529530')

# 3. Component 3: Supervisor (32 bytes)
comp3 = bytes.fromhex('6c8737ba4c7a107a4c01f44dc0f42df58a36735d3aca1bcaba67191ffea05225')

fixture = comp1 + comp2 + comp3
assert len(fixture) == 96, f"Invalid fixture length {len(fixture)}"

def rol8(val, r):
    r &= 7
    return ((val << r) | (val >> (8 - r))) & 0xff

# Derive private key using boarddiag algorithm
out = bytearray(32)
w6 = 7
for x0 in range(1, 33):
    w3 = (x0 - 1) & 7
    w2 = w6 & 0x1f
    w1 = fixture[x0 + 31]
    w8 = fixture[96 - x0]
    w2_byte = fixture[w2]
    w1_rot = rol8(w1, w3)
    w2_xor = w2_byte ^ w8
    w6 = (w6 + 13) & 0xffffffff
    out[x0 - 1] = w2_xor ^ w1_rot

priv_bytes = bytes(out)
priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
pub_bytes = priv_key.public_key().public_bytes_raw()
expected_pub = '8bc22f9dad276d4302d75f5bf0dc6ab30a50ff102d9d7b96de69fec36048ed4c'
assert pub_bytes.hex() == expected_pub, f"Public key mismatch: {pub_bytes.hex()}"

def crc16_modbus(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc

def solve(host, port):
    print(f"[*] Connecting to {host}:{port}...")
    s = socket.create_connection((host, port), timeout=10)
    f = s.makefile('rw', buffering=1)
    
    banner = f.readline().strip()
    print(f"[*] Banner: {banner}")
    
    # Step 1: Request Challenge Nonce (FC 0x41)
    fc41_payload = b"\x17\x41\x53\x39\x00\x02"
    crc = crc16_modbus(fc41_payload)
    fc41_frame = fc41_payload + struct.pack('<H', crc)
    cmd1 = f"XFER {fc41_frame.hex()}\n"
    print(f"[>] Sending FC 0x41: {cmd1.strip()}")
    f.write(cmd1)
    f.flush()
    
    resp1_hex = f.readline().strip()
    print(f"[<] Response 1: {resp1_hex}")
    
    resp1 = bytes.fromhex(resp1_hex)
    unit_id, fc, nonce_len = resp1[0], resp1[1], resp1[2]
    nonce = resp1[3:35]
    print(f"[*] Received nonce ({len(nonce)} bytes): {nonce.hex()}")
    
    # Step 2: Sign Challenge (FC 0x42)
    msg = b"SOLSTICE9/maintenance/v1" + nonce
    sig = priv_key.sign(msg)
    print(f"[*] Generated Ed25519 signature: {sig.hex()}")
    
    fc42_payload = b"\x17\x42" + sig
    crc2 = crc16_modbus(fc42_payload)
    fc42_frame = fc42_payload + struct.pack('<H', crc2)
    cmd2 = f"XFER {fc42_frame.hex()}\n"
    print(f"[>] Sending FC 0x42: {cmd2.strip()[:30]}... ({len(cmd2)} bytes)")
    f.write(cmd2)
    f.flush()
    
    resp2_hex = f.readline().strip()
    print(f"[<] Response 2: {resp2_hex}")
    
    resp2 = bytes.fromhex(resp2_hex)
    unit_id, fc, flag_len = resp2[0], resp2[1], resp2[2]
    flag = resp2[3:3+flag_len].decode('utf-8', errors='replace')
    print(f"\n[+] FLAG: {flag}\n")
    return flag

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "34.89.230.22"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 30312
    solve(host, port)

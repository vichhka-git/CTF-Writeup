#!/usr/bin/env python3
"""
Ghost in the Machine - Challenge 30 Solver
CSAW CTF Qualifications 2026

Vulnerability/Mechanism:
1. capture.pcap has a corrupted magic byte (0xc4 instead of 0xd4).
2. The capture contains 504 UDP packets with payload b'PING'.
3. Two discrete IP TTL values are present:
   - TTL 113: Decoy/noise packets.
   - TTL 64: The true covert channel beacon.
4. The UDP source port column for TTL 64 packets changes every 8 packets in groups:
   40115 ('s'), 40104 ('h'), 40052 ('4'), 40100 ('d'), 40111 ('o'), 40119 ('w')
   repeating 8 times (48 groups total, spelling "sh4dow").
5. The inter-packet arrival times (deltas) between consecutive TTL 64 packets encode bits:
   - ~50 ms (0.05 s) = bit 0
   - ~150 ms (0.15 s) = bit 1
   There are exactly 384 deltas, forming 48 bytes (MSB first).
6. XORing the 48 recovered bytes with the key "sh4dow" reveals the flag:
   csaw{t1m1ng_1s_3v3ryth1ng_1n_th3_s1l3nt_ch4nn3l}
"""

import sys
import io
from pathlib import Path
from scapy.all import rdpcap, IP, UDP

def solve():
    challenge_dir = Path(__file__).resolve().parent.parent
    pcap_path = challenge_dir / "files" / "capture.pcap"
    
    with open(pcap_path, "rb") as f:
        data = bytearray(f.read())
        
    # Fix corrupted pcap magic byte if needed
    if data[0] == 0xc4:
        data[0] = 0xd4
        
    # Parse packets from memory
    pkts = rdpcap(io.BytesIO(data))
    
    # Filter for TTL 64 packets
    t64 = [p for p in pkts if p[IP].ttl == 64]
    
    # Extract inter-packet deltas
    deltas = [float(t64[i+1].time - t64[i].time) for i in range(len(t64)-1)]
    assert len(deltas) == 384, f"Expected 384 deltas, got {len(deltas)}"
    
    # Threshold at 100ms: < 0.1s is 0, >= 0.1s is 1
    bits = [0 if d < 0.1 else 1 for d in deltas]
    
    # Pack 384 bits into 48 bytes (MSB first)
    raw_bytes = bytes(int("".join(map(str, bits[i*8:(i+1)*8])), 2) for i in range(48))
    
    # Extract key from source ports
    # Port values are 40000 + ord(c)
    key_chars = []
    current_port = None
    for p in t64:
        sp = p[UDP].sport
        if sp != current_port:
            key_chars.append(chr(sp - 40000))
            current_port = sp
            if len(key_chars) == 6:
                break
    key = "".join(key_chars).encode("ascii")
    
    # Decrypt via repeating-key XOR
    flag_bytes = bytes(b ^ key[i % len(key)] for i, b in enumerate(raw_bytes))
    flag = flag_bytes.decode("utf-8")
    
    print(f"Key: {key.decode('ascii')}")
    print(f"Flag: {flag}")
    return flag

if __name__ == "__main__":
    solve()

# Writeup: P_WIRE: The Line Tap

- **Category**: Forensics / Network
- **Points**: 500
- **Status**: Completed & Submitted
- **Flag**: `flag{s34l3d_tunn3l_dfeaf75729}`

---

## 1. Challenge Overview
Analyzed uplink2.pcap, identified custom stream cipher framing, recovered keystream, and decrypted the sealed tunnel payload.

---

## 2. Vulnerability / Attack Vector Analysis
The target system exhibited weaknesses in its security architecture, allowing an attacker to bypass authorization filters, forge credentials, or abuse logical inconsistencies to recover the protected clearance token.

---

## 3. Exploit / Solution Methodology
1. **Reconnaissance**: Explored exposed ports, service endpoints, or binaries.
2. **Identification**: Discovered the core flaw and crafted the proof-of-concept payload.
3. **Execution**: Sent the constructed payload/exploit to the target service to retrieve the clearance token.

---

## 4. Flag
```text
flag{s34l3d_tunn3l_dfeaf75729}
```

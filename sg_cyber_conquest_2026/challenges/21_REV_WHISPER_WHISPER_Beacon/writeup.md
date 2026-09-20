# Writeup: REV_WHISPER: WHISPER Beacon

- **Category**: Reverse Engineering
- **Points**: 250
- **Status**: Completed & Submitted
- **Flag**: `flag{wh1sp3r_d3r1v3d_2548a2ad9d}`

---

## 1. Challenge Overview
Reversed proprietary WHISPER binary, implemented authentication challenge-response protocol, and decrypted token.

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
flag{wh1sp3r_d3r1v3d_2548a2ad9d}
```

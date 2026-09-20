# Writeup: P_SIGN: Signing Authority

- **Category**: Cryptography
- **Points**: 550
- **Status**: Completed & Submitted
- **Flag**: `flag{n0nc3_r3us3_00924d6eb1}`

---

## 1. Challenge Overview
ECDSA nonce reuse vulnerability across two clearance signatures, allowing recovery of the private key to sign an arbitrary clearance request.

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
flag{n0nc3_r3us3_00924d6eb1}
```

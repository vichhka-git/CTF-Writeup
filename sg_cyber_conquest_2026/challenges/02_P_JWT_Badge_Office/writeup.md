# Writeup: P_JWT: Badge Office

- **Category**: Web / Cryptography
- **Points**: 550
- **Status**: Completed & Submitted
- **Flag**: `flag{4lg_c0nfus10n_d33e454dea}`

---

## 1. Challenge Overview
Algorithm confusion attack swapping RS256 with HS256, signing the forged warden badge with the raw bytes of the public key.

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
flag{4lg_c0nfus10n_d33e454dea}
```

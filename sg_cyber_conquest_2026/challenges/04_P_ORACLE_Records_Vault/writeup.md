# Writeup: P_ORACLE: Records Vault

- **Category**: Cryptography / Web
- **Points**: 550
- **Status**: Completed & Submitted
- **Flag**: `flag{p4dd1ng_0r4cl3_fcdce1b1e6}`

---

## 1. Challenge Overview
Padding oracle attack against CBC-mode session cookies, decrypting the auditor token and forging a warden session token.

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
flag{p4dd1ng_0r4cl3_fcdce1b1e6}
```

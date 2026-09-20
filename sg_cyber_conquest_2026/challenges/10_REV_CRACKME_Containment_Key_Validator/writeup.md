# Writeup: REV_CRACKME: Containment Key Validator

- **Category**: Reverse Engineering
- **Points**: 200
- **Status**: Completed & Submitted
- **Flag**: `flag{sb0x_f33db4ck_unw0und}`

---

## 1. Challenge Overview
Reversed 17-byte validation algorithm involving S-box permutation feedback and circular rotation.

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
flag{sb0x_f33db4ck_unw0und}
```

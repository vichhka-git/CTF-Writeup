# Writeup: P_QUORUM: Clearance Quorum

- **Category**: Web / Logic Flow
- **Points**: 700
- **Status**: Completed & Submitted
- **Flag**: `flag{tw0_s1gn4tur3s_0f4760f1f1}`

---

## 1. Challenge Overview
TOCTOU signature flaw: request endorsed under low-risk routine scope, then amended scope to containment master key while retaining signatures.

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
flag{tw0_s1gn4tur3s_0f4760f1f1}
```

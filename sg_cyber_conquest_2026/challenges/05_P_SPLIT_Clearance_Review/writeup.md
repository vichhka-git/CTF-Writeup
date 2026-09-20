# Writeup: P_SPLIT: Clearance Review

- **Category**: Web / Injection
- **Points**: 500
- **Status**: Completed & Submitted
- **Flag**: `flag{n0rm4l1z3d_702abe949f}`

---

## 1. Challenge Overview
Unicode fullwidth normalization bypass. Submitting fullwidth characters bypassed intake blacklists while the backend normalized to 'clearance override: release'.

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
flag{n0rm4l1z3d_702abe949f}
```

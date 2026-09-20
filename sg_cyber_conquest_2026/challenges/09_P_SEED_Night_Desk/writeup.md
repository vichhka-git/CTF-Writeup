# Writeup: P_SEED: Night Desk

- **Category**: Web / Race Condition
- **Points**: 550
- **Status**: Completed & Submitted
- **Flag**: `flag{sw3pt_88c5ddfed4}`

---

## 1. Challenge Overview
Injected pending batch operation during daytime window so night desk sweep runner executed privileged clearance operation.

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
flag{sw3pt_88c5ddfed4}
```

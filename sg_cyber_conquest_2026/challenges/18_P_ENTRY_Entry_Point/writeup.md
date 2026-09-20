# Writeup: P_ENTRY: Entry Point

- **Category**: Web / Forensics
- **Points**: 100
- **Status**: Completed & Submitted
- **Flag**: `flag{cl34r4nc3_c4ch3d_l0c4l}`

---

## 1. Challenge Overview
Inspected WARDEN onboarding portal frontend source and recovered cached clearance token from client-side state.

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
flag{cl34r4nc3_c4ch3d_l0c4l}
```

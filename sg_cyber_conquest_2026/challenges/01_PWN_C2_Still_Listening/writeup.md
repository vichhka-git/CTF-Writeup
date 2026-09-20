# Writeup: PWN_C2: Still Listening

- **Category**: Pwn / Binary Exploitation
- **Points**: 400
- **Status**: Completed & Submitted
- **Flag**: `flag{c2_h34p_u4f_8ba3ee3ba9}`

---

## 1. Challenge Overview
Heap Use-After-Free in the C2 service allowing arbitrary read/write, leaking libc base, and executing system('/bin/sh').

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
flag{c2_h34p_u4f_8ba3ee3ba9}
```

# Writeup: SQ_NOTICE9: The Watch Officer's Template

- **Category**: Forensics / Reversing
- **Points**: 450
- **Status**: Completed & Submitted
- **Flag**: `flag{n0t1c3_n1n3_38fe10b9b2}`

---

## 1. Challenge Overview
Extracted NOTICE09.ZIP print spool template, analyzed PostScript stream, and recovered Notice 9 clearance designation.

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
flag{n0t1c3_n1n3_38fe10b9b2}
```

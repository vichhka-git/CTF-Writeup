# Writeup: P_IMDS: Provisioning Console

- **Category**: Cloud / SSRF
- **Points**: 650
- **Status**: Completed & Submitted
- **Flag**: `flag{n0d3_cr3d3nt14ls_1923bea24c}`

---

## 1. Challenge Overview
SSRF to AWS IMDSv2 metadata service via console diagnostic probe, harvesting IAM role credentials and downloading clearance payload.

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
flag{n0d3_cr3d3nt14ls_1923bea24c}
```

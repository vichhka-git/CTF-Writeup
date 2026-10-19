# Hooked

- **Category:** Forensics
- **Points:** 25
- **Flag:** `deadface{http://demonne-secure-portal.net/login?ref=vpn_auth&token=df4e91bc}`

## Challenge

De Monne Financial has detected suspicious outbound traffic originating from workstation `DEMONNE-WS04`, assigned to employee Fletcher Kampeter in the Finance division. A credential submission was logged against an unknown external host at *10:23 AM on March 14, 2025* - during normal business hours. Browser artifacts have been imaged from the machine and packaged for analysis. DEADFACE is suspected of running a targeted spearphishing campaign against De Monne personnel. It's unclear how deep the access goes, but finding the entry point is the first step. Inspect the artifacts. Find the URL the

## Solution

Chrome History visit 6 = external host visit 2025-03-14 10:23:44 from Gmail session (from_visit=5), 66-byte ASCII URL; Login Data saved credential row with identical date_created 13386421424000000 + password blob ENCRYPTED_PHISH, action_url /auth/verify; cache f_000006 = cached fake portal page with hidden token df4e91bc; f_000009 JS exfil to 185.220.101.47/collect

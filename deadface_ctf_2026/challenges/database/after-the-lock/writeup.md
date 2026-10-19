# After the Lock

- **Category:** Database
- **Points:** 150
- **Flag:** `deadface{VELT-0137}`

## Challenge

<honeypot-string-withheld> Once a clinical trial's database is locked, results are frozen — any edit after the data-lock date is a protocol violation and a fingerprint of tampering. Aurora Health recorded the official lock date for the Veltrexa study right in the studies table. Find the subject whose primary efficacy result (measure = 'primary_efficacy_delta') was modified after the study's data-lock date, and report their subject code. Use the provided MySQL shell. Submit the subject code as `deadface{subject_code}`. Example: `deadface{ABCD-0101}`. [Access Database](https://aurora.dctf.io)

## Solution

Veltrexa (study 1) data_lock_date=2025-12-01; subject VELT-0137 primary_efficacy_delta was modified 2025-12-06 23:14:00 by mreyes (old 2.3 -> new 6.0)

# Heavy Hand

- **Category:** Database
- **Points:** 100
- **Flag:** `deadface{BR2938471}`

## Challenge

One Aurora prescriber dispensed far more Schedule II medication than anyone else in the final quarter of 2025 — the classic signature of drug diversion. Using the `aurora_pharmacy` database, find the prescriber with the highest total quantity of Schedule II medication dispensed between 2025-10-01 and 2025-12-31, and report their DEA number. Use the provided MySQL shell. Submit the DEA number as `deadface{DEA}`. Example: `deadface{AB1234567}`. [Access Database](https://aurora.dctf.io)

## Solution

Database investigation into prescription drug diversion within Aurora Health. By analyzing the `aurora_pharmacy` database via the `aurora.dctf.io` terminal session, we joined dispensing records, prescriptions, prescribers, and drug formulary data for Q4 2025 (2025-10-01 to 2025-12-31). Prescriber Marcus Reyes (`prescriber_id` = 2, DEA `BR2938471`) was identified as having dispensed 5,220 units of Schedule II controlled substances, exceeding the next highest prescriber by nearly 35x.

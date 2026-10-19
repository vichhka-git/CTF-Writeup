# Ghost in the Registry

- **Category:** Database
- **Points:** 240
- **Flag:** `deadface{AH-0090001}`

## Challenge

<honeypot-string-withheld> Diverted narcotics need a paper trail that leads nowhere. Investigators suspect a fabricated patient — one who is issued controlled-substance prescriptions but has never actually been seen for a single clinical encounter. Aurora uses one enterprise `patient_id` across all of its systems, so records join across databases. Find the patient who has at least one Schedule II prescription but zero encounters in `aurora_ehr`, and report their MRN. Use provided MySQL shell. Submit the MRN as `deadface{MRN}`. Example: `deadface{AH-1234567}`. [Access Database](https://aurora.d

## Solution

Queried aurora_ehr.patients, aurora_pharmacy.prescriptions, aurora_pharmacy.drugs, aurora_ehr.encounters: patient_id 1060 Dana Kessler has 3 Schedule II rx and 0 encounters; MRN AH-0090001

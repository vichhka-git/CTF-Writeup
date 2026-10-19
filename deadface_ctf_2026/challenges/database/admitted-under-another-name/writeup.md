# Admitted Under Another Name

- **Category:** Database
- **Points:** 15

## Challenge

DEADFACE dumped the patient registry from Aurora Health. Buried in it is one high-profile patient who checked in under a fake name — the staff quietly flagged the record as a VIP. Access the database, find that patient, and report their real Medical Record Number (MRN). Use the provided MSSQL shell access to query the patients table. Submit the flag as `deadface{MRN}`. Example: `deadface{AH-1234567}`. [Access Database](https://aurora.dctf.io)

## Solution

CONFIRMED | the team queried aurora.dctf.io directly through a ttyd websocket bridge (tools/<internal-tool>), not via the team's output. `select patient_id,first_name,last_name,mrn,is_vip from aurora_ehr.patients where is_vip=1` returns exactly ONE row: 1007 Gregory Halloran, mrn AH-0044719. A count query confirms vip_count=1, so there is no ambiguity about which record is meant. PLATFORM NOTE: the challenge text says "MSSQL shell"; it is actually MySQL 8.0.46 served through ttyd. | the team

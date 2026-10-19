# SQL Skillz

- **Category:** Aurora Patient Zero
- **Points:** 50
- **Flag:** `deadface{Candesartan}`

## Challenge

<honeypot-string-withheld> For this task, you need to continue your examination of the Aurora Patient Portal application. After completing *Info Leaks* and *Down the Rabbit Hole*, you have collected the patient data that is needed to query the application database file. Use the data collected to determine what medications the current patient is taking *other than Ibuprofen*. Submit the result as the flag as `deadface{Name}`.

## Solution

The challenge requires determining what medication the patient is taking other than Ibuprofen using data collected from *Info Leaks* and *Down the Rabbit Hole*.
From *Down the Rabbit Hole*, the patient ID is `PID-847261` (`pid = 847261`).
Querying the bundled SQLite database `aurora_meds.sqlite` (from `Payload/aurora-patient-portal.app/` inside `AuroraPatientPortal.ipa`) for `pid = 847261`:
```sql
SELECT medication_1, medication_2 FROM medications WHERE pid=847261;
```
Yields:
- `medication_1`: `Ibuprofen`
- `medication_2`: `Candesartan` Flag: `deadface{Candesartan}`.

# The Original Reading

- **Category:** Database
- **Points:** 70
- **Flag:** `deadface{2.3}`

## Challenge

Aurora Pharmaceuticals ran a Phase III trial for a drug called Veltrexa, and the trial's EDC (electronic data capture) system keeps a full audit trail of every edit in a `data_changes` table. Most entries are routine source-data corrections — but exactly one rewrote a primary efficacy endpoint, quietly changing the number to make the drug look like it worked. Recover the original value that was overwritten. Use the provided MySQL shell. Submit the value exactly as it appears in the audit trail, wrapped in the flag. Example: `deadface{1.4}`. [Access Database](https://aurora.dctf.io)

## Solution

`aurora_trials` is the Veltrexa Phase III electronic data capture (EDC) database on the
organizer's `aurora.dctf.io` MySQL 8.0.46 instance. Its audit trail `data_changes` holds
**9 rows total**, and the shape of the table is the tell: | change_id | table_name | record_ref | field_name | old_value | new_value | changed_by | changed_at | reason |
|---|---|---|---|---|---|---|---|---|
| 500001 | results | VELT-0137 | **primary_efficacy_delta** | **2.3** | **6.0** | mreyes | 2025-12-06 23:14:00 | Query resolution per monitor |
| 500002–500009 | subjects | VELT-01xx | arm / status / enrollment_date | `(prior)` | `(corrected)` | achang, tstack, jokafor | 2025-07-11 … 2025-11-04 | Source data verification | Eight rows are the routine source-data corrections the description warns about — and their
`old_value`/`new_value` are literally the placeholder strings `(prior)` and `(corrected)`,
so no original value was ever preserved for them. **Exactly one row carries a real
before/after pair on a clinical measurement**, and field_name is
`primary_efficacy_delta` — the trial's primary efficacy endpoint. The audit trail is
self-identifying: `select field_name, count(*) … group by field_name` returns
`primary_efficacy_delta` with n=1. The flag is that row's `old_value`, submitted **exactly as stored**. The column is
`varchar(80)`; the stored string is 3 characters, `2.3` — there is no trailing zero, and
`concat('<',old_value,'>')` returns `<2.3>` with `length(old_value)=3`, which rules out
hidden whitespace or padding.

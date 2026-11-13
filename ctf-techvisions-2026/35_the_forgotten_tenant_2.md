## 35 — The Forgotten Tenant - 2 (Cloud)

1. Open `Access_key_ID.docx`. It contains a read-only access key and secret for the migration archive bucket.
2. List `s3://tvx-forgotten-tenant-migration-archive-pro0hid4/`. Read `README-OLD.md`, `asset-inventory.csv`, `configs/etl-worker.conf.bak`, `exports/iam-export-snapshot.json`, and `tickets/TVX-4471-export.txt`.
3. The archive reveals an external-ID prefix `fthK52` and suffix `ycGCAX`. Combine them as `fthK52ycGCAX`.
4. Assume the legacy migration role `arn:aws:iam::400875701859:role/tvx-forgotten-tenant-legacy-migration-role`. Its inline policy permits assuming `arn:aws:iam::400875701859:role/tvx-forgotten-tenant-*`.
5. Assume `tvx-forgotten-tenant-incident-response-role`. Its policy permits only `s3:GetObject` on `case-*/handoff-*/evidence.json`.
6. Read `s3://tvx-forgotten-tenant-forensics-pro0hid4/case-ab5396cd/handoff-RYII91T48V/evidence.json`. The `final_flag` field is the answer.

`TVX{6N8at90xLFvdgyma648o}`

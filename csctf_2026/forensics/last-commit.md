# Last Commit

**Category:** Forensics · **Points:** 450 · **Flag:** `CSCTF{last_commit_40f3b19d5a11601e9d5e5bf0c7a3bcb6248b5667764f25549b607c27396ccf5f}`

## What the handout gives you

The handout is `last-commit.zip` (84,979 bytes, SHA-256 `06da868e7ceeef1c96651cf1307033f7b37b65e235f8a121ea599166f85279a1`), containing an acquired SQLite database pair and job specification artifacts:

- `registry.sqlite` — 36,864-byte SQLite 3 database file (9 pages of 4096 bytes).
- `registry.sqlite-wal` — 37,112-byte Write-Ahead Log consisting of a 32-byte header and 9 frames (each 24-byte header plus 4096-byte page image).
- `delivery.csv` — 197-byte delivery manifest mapping 12 parcel IDs to sequential positions 1 through 12 for export job `LR-731`.
- `export-profile.md` — specification of worker semantics, schema, exact query, tab-separated formatting rules, and hashing instructions.
- `provenance.json`, `README.txt`, `SHA256SUMS` — incident provenance notes, integrity hashes, and warnings against opening the preserved database with automatic WAL replay.

## Walkthrough

1. **Understand worker execution semantics.** According to `export-profile.md`, the export worker processes job `LR-731` in an immediate transaction: it stages the manifest parcels, queries their ownership titles, updates `export_job` from `QUEUED` to `COMPLETED`, and commits. Subsequent modifications in later transactions restored or altered title records, so querying the fully replayed modern view yields incorrect records. The export must be reconstructed using the exact database state at the moment job `LR-731` transitioned to `COMPLETED`.

2. **Parse WAL frames and commit boundaries.** A SQLite WAL file begins with a 32-byte header followed by frames of 4120 bytes (24-byte frame header and 4096-byte page). In each frame header, bytes 4–7 contain the big-endian 32-bit `commit_sz` field. A non-zero value indicates a transaction commit boundary that sets the total database page count; a zero value indicates an intermediate page update.

```bash
wal-dump registry.sqlite-wal
```

Inspecting the 9 frames reveals six commit points:
- Frame 1: page 2, commit_sz = 9 (Commit 1)
- Frame 2: page 6, commit_sz = 0
- Frame 3: page 7, commit_sz = 9 (Commit 2)
- Frame 4: page 8, commit_sz = 0
- Frame 5: page 9, commit_sz = 9 (Commit 3)
- Frame 6: page 8, commit_sz = 9 (Commit 4)
- Frame 7: page 6, commit_sz = 0
- Frame 8: page 7, commit_sz = 9 (Commit 5)
- Frame 9: page 2, commit_sz = 9 (Commit 6)

3. **Identify the LR-731 commit point.** Reconstructing the SQLite database state at each commit point by copying `registry.sqlite` and applying WAL pages up to that frame allows inspecting table `export_job`:
- Commits 1 and 2 (Frames 1 and 3): `export_job` is empty.
- Commit 3 (Frame 5): `export_job` contains `('LR-731', 'QUEUED')`.
- Commit 4 (Frame 6): `export_job` contains `('LR-731', 'COMPLETED')`.
- Commits 5 and 6 (Frames 8 and 9): `export_job` remains `COMPLETED`.

The transition from `QUEUED` to `COMPLETED` occurred precisely in Commit 4 at Frame 6.

4. **Isolate the database state after Frame 6.** To reconstruct the historical database without corrupting the evidence, copy `registry.sqlite` and overlay pages updated by WAL frames 1 through 6. In Frame 6's state, parcel records reflect altered ownership before the subsequent reconciliation. Comparing Frame 6 with Frame 8 reveals five title records that were changed in Frame 8 (parcels 1202, 1205, 1209, and 1214 had different holder IDs and basis point allocations).

5. **Load manifest and execute the export query.** Open the database reconstructed at Frame 6, create a temporary table `manifest(job_id TEXT, position INTEGER, parcel_id INTEGER)`, and import `delivery.csv`. Run the export query specified in the profile:

```sql
SELECT m.position,p.parcel_id,p.district,p.plot_ref,h.registry_ref,t.interest_bps,t.instrument_ref
FROM manifest AS m JOIN parcel AS p ON p.parcel_id=m.parcel_id
JOIN title AS t ON t.parcel_id=p.parcel_id JOIN holder AS h ON h.holder_id=t.holder_id
WHERE m.job_id='LR-731' ORDER BY m.position ASC,h.registry_ref COLLATE BINARY ASC;
```

6. **Format and hash the output.** Format the header line and query result rows with single tab characters between fields and LF after each line. No quotes, BOM, or trailing spaces may be added. Computing SHA-256 over this raw byte sequence yields:

`40f3b19d5a11601e9d5e5bf0c7a3bcb6248b5667764f25549b607c27396ccf5f`

## Answer

Prefixing the digest with the submission wrapper gives the flag:

`CSCTF{last_commit_40f3b19d5a11601e9d5e5bf0c7a3bcb6248b5667764f25549b607c27396ccf5f}`

## Notes

Opening `registry.sqlite` directly in standard SQLite tools automatically recovers and checkpoints the entire WAL file, advancing the database to Frame 9 where altered titles have already been overwritten. Always work on an isolated copy and truncate the WAL to Frame 6 or patch the database pages directly.

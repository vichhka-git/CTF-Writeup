# CSAW CTF 2026 - Roll Call (OSINT) Writeup

## Challenge Overview
- **Category:** OSINT
- **Points:** 150
- **Target:** Investigate an incident response case file (`d.zip`) containing internal investigation records for Halcyon Therapeutics. Two subjects who met escalation criteria were mistakenly omitted from the active monitoring watchlist.
- **Flag Format:** `csaw{handle_handle}` (handles lower case, sorted alphabetically, joined by underscore).

## Investigation and Analysis
1. Extracted `d.zip` into `agent_workspace/roll-call/`, containing:
   - `case_file/protocol.md`
   - `case_file/watchlist.csv`
   - `case_file/intake.db` (SQLite database)
   - `comms/forum_dump.json`, `dm_export.json`, `email_intake.mbox`
   - `timeline/escalations.log`

2. According to `protocol.md`, `intake.db` is the single authoritative system of record. Reconciliations between sources must be performed at the person level (`person_id`), because multiple handles map to single individuals in `identities`.

3. By examining `intake.db`:
   - `escalations` table records all escalated posts and their associated handles.
   - `watchlist` table records subjects currently on the active monitoring watchlist.
   - `identities` table maps each `handle` to a canonical `person_id`.

4. Running a set difference between escalated persons and watchlist persons:
   - Escalated persons: `{P01, P02, P03, P04, P05, P06, P07, P08, P09, P10}`
   - Watchlist persons: `{P01, P02, P04, P05, P06, P07, P08, P10}`
   - Missing persons: `P03` and `P09`

5. Looking up their primary handles in `identities`:
   - `P03` -> `HALCYONLEAKS` -> lower case `halcyonleaks`
   - `P09` -> `still_water_77` -> lower case `still_water_77`

6. Alphabetical ordering:
   - `halcyonleaks` < `still_water_77`

7. Canonical Flag:
   `csaw{halcyonleaks_still_water_77}`

## Reproduction
Run `solve.py`:
```bash
python3 solve.py
```
Output:
```
csaw{halcyonleaks_still_water_77}
```

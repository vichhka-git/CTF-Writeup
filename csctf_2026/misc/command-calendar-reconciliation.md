# Command Calendar Reconciliation

**Category:** misc · **Points:** 120 · **Flag:** `CSCTF{ADaz3C5y6rngUKdk3Um4Cv7Z}`

## What the handout gives you

An incident response instance running a calendar coordination service for the Vardanne Civil Continuity Service. The HTTP interface exposes three endpoints:

- `GET /brief` — JSON specification containing the audit horizon (`2026-09-07T00:00:00Z` to `2026-09-22T00:00:00Z`), recurrence evaluation rules, and the schema expected by the attestation verifier.
- `GET /case.ics` — an exported iCalendar (RFC 5545) file containing recurring emergency relay activations with detached overrides.
- `POST /attest` — receiver accepting the verified activation sequence as an RFC 8259 JSON payload.

## Walkthrough

### 1. Fetch the specification and calendar

Retrieve the operational window and calendar export from the challenge instance:

`curl -s http://<host>:<port>/brief`

`curl -s http://<host>:<port>/case.ics -o case.ics`

The brief specifies a strict observation window: `horizon_start_utc` at `2026-09-07T00:00:00Z` and `horizon_end_utc` at `2026-09-22T00:00:00Z`. An activation belongs to the set if and only if its actual `DTSTART` falls in `[horizon_start_utc, horizon_end_utc)`. Overlapping intervals spanning across boundary points without starting in the window are excluded.

### 2. Parse the base recurrence series

`case.ics` defines three emergency relays across three distinct UIDs:

1. `relay-1-...`: base start `2026-09-03T08:00:00Z`, daily recurrence with `INTERVAL=2` for 12 counts, explicit addition `RDATE: 20260908T080000Z`, and exclusion `EXDATE: 20260913T080000Z`.
2. `relay-2-...`: base start `2026-09-07T10:00:00Z`, weekly recurrence with `BYDAY=MO,WE,FR` for 12 counts, plus `RDATE: 20260912T100000Z`.
3. `relay-3-...`: base start `2026-09-04T13:00:00Z`, daily recurrence with `INTERVAL=2` until `2026-09-22T13:00:00Z`, plus `RDATE: 20260907T130000Z`.

Nominal recurrence expansion computes every scheduled occurrence. `EXDATE` removes the nominal activation on `2026-09-13T08:00:00Z` before detached evaluations take place.

### 3. Resolve detached recurrence replacements

The calendar contains two detached `VEVENT` entries referencing `relay-1` via `RECURRENCE-ID`:

- Detached instance 1 specifies `RECURRENCE-ID: 20260921T080000Z` with replacement `DTSTART: 20260922T070000Z`. The original occurrence sat inside the window, but the rescheduled time falls after `2026-09-22T00:00:00Z`. It is dropped from the audit set.
- Detached instance 2 specifies `RECURRENCE-ID: 20260925T080000Z` with replacement `DTSTART: 20260907T070000Z`. The original occurrence sat outside the window on September 25, but the rescheduled time moves into the window on September 7. It is retained with its original `recurrence_id_utc` preserved.

### 4. Filter and sort activations

Collecting all qualifying activations within `[2026-09-07T00:00:00Z, 2026-09-22T00:00:00Z)` yields exactly 24 activations across the three relays. Each record requires five fields:

- `uid`: string matching the event UID.
- `recurrence_id_utc`: original recurrence timestamp in `YYYY-MM-DDTHH:MM:SSZ` format (null for non-detached instances).
- `start_utc`: effective activation start timestamp.
- `end_utc`: effective activation end timestamp.
- `category`: literal `"EMERGENCY-RELAY"`.

Sort the 24 records in strictly ascending order by `start_utc`.

## Answer

Transmit the formatted JSON array wrapped in `{"activations": [...]}` to `POST /attest`:

`curl -s -H "Content-Type: application/json" -d @attestation.json http://<host>:<port>/attest`

The server attestation check succeeds and outputs the restoration code:

`CSCTF{ADaz3C5y6rngUKdk3Um4Cv7Z}`

## Notes

Calendars are generated dynamically per instance launch. The UIDs, dates, and detached shifts will differ on a fresh container, but the recurrence semantics remain identical.

The primary trap is detached instance evaluation. Per RFC 5545, detached instances are not separate events; they replace a specific recurrence identified by `RECURRENCE-ID`. An event originally scheduled outside the window can shift into the window, and an event inside can shift out. Filtering before applying detached replacements causes verification failures.

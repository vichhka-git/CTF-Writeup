# Sunshine CTF 2026 Writeup: Planetary Probe

- **Category:** web
- **ID:** 15
- **Points / Solves:** 496 pts / 64 solves
- **Connection:** `https://planetary.web.2026.sunshinectf.games/`
- **Flag:** `sun{bl1nd_psqli_2_rc3_p4Nd0FyZt8k2}`

---

## Challenge

> The Galactic Federation has opened public access to its Planetary Probe Directory, a database of known planets and their telemetry signatures.
> Your mission is to interface with the probe console and uncover hidden data the Federation would rather keep secret.
> 
> The console seems… minimal. No verbose errors, no detailed output — just “signal detected” or “no signal”.
> Can you find a way to communicate with the system, bypass its limited responses, and recover the hidden flag?

---

## Summary

Blind PostgreSQL injection behind a one-bit oracle, escalated to RCE with `COPY ... FROM PROGRAM`.

## Solution

`/probe?planet=` is injectable. The oracle is a **HEAD request read off `content-length`**:
`5622` = TRUE, `5604` = FALSE — a zero-byte body, saving ~5.6 KB per probe on a service shared with
600 teams.

**Two rules that are not optional here.**

1. **Error is byte-identical to false.** An unbalanced quote returns exactly `5604`; there is no 500
   and no third length anywhere. A broken payload therefore reports every bit as zero and yields a
   confident, entirely wrong answer. Every predicate must be sent with its negation and required to
   produce `5622`/`5604` in some order.
2. **The app lowercases the input** before building the query. String literals are case-folded;
   numbers and SQL keywords are not. So `substring(x,1,1)='P'` is false even when the character is
   `P`, and every `LIKE '%keyword%'` search is case-blind — fold the *column*, not the pattern.
   A pattern containing `sun{` must be built from `chr()`, because `pg_stat_activity` holds your own
   query and a literal pattern self-matches.

**Enumeration.** Backend is PostgreSQL (`string_agg`, `current_database()` work; `group_concat`,
`@@version`, `sqlite_version`, `sqlite_master` error). Schema `public` holds exactly four relations:
`planets`, `planets_id_seq`, `planets_pkey`, `zleak`. `planets` is `id,name,diameter_km,description`
over 8 rows. `zleak` has one row, one column `v`, whose value is the 19-character string
`select v from zleak` — a hint pointing at itself. `sun{` appears nowhere reachable, and the user
`probe` is not superuser, so `pg_read_file`/`pg_ls_dir` error.

**The finish.** With the database exhausted, the route was command execution. After switching the
transaction read-write, `COPY ... TO/FROM PROGRAM` is available:

```sql
COPY (SELECT 1) TO PROGRAM 'true';   -- 5622
COPY (SELECT 1) TO PROGRAM 'false';  -- 5604
COPY <temp> FROM PROGRAM 'printf sun{probe}';   -- verified round-trip
```

That gives a boolean-gated command execution primitive; reading the flag file through it and
extracting byte-by-byte yields `sun{bl1nd_psqli_2_rc3_p4Nd0FyZt8k2}`.

## Ruled Out

- **Large objects**: `pg_largeobject_metadata` has nine rows, but every object readable by `probe` is
  zero-length. Ruled out per-object with a paired control, because on this oracle a permission denial
  and an empty object are indistinguishable.

  Two methodology notes on that, both learned the hard way:

  - **Do not batch it.** `lo_get` *throws* on permission denial, and one throw aborts the whole
    statement — so `EXISTS(SELECT 1 FROM pg_largeobject_metadata WHERE position(... in lo_get(loid))>0)`
    lets a single unreadable object poison the query even when the other eight are readable. It
    teaches you nothing about the readable ones. One loid at a time, each with its own control.
  - **Answer readability without calling `lo_get` at all.** `pg_largeobject_metadata` is itself
    readable and carries the ACL columns, so two probes settle it:

    ```sql
    (SELECT count(*) FROM pg_largeobject_metadata WHERE lomacl IS NULL) = 9
    EXISTS(SELECT 1 FROM pg_largeobject_metadata
           WHERE lomowner = (SELECT oid FROM pg_roles WHERE rolname = current_user))
    ```

    `lomacl IS NULL` means the default owner-only ACL. If all nine are NULL and none is owned by
    `probe`, the objects are closed *by privilege* rather than empty — and an author does not gate a
    flag behind a privilege with no escalation path, so they are scenery.
  - A direct `SELECT` from `pg_largeobject` has required superuser since PostgreSQL 9.0, so a null
    result there is expected and uninformative.
- **`convert_from(data,'UTF8')`** must not be used to search binary: it *throws* on invalid UTF-8,
  and a throw is byte-identical to false. `position(decode('73756e7b','hex') in lo_get(oid))` is
  binary-safe and its literals are already lowercase.
- Mixed-case identifiers: `relname <> lower(relname)` and `attname <> lower(attname)` both false.
- `dblink` / `postgres_fdw`: not installed.

## What would have been faster

Every dead end above is a *read* surface — tables, columns, catalog text, configuration parameters,
role names, large objects. The solution was not a place the data was hiding; it was a capability the
database handed us. `COPY ... TO/FROM PROGRAM` requires membership in `pg_execute_server_program`, so
the single most informative probe on this target was never run:

```sql
-- not "what are the roles called", but "what do they let us do"
EXISTS(SELECT 1 FROM pg_auth_members m
        JOIN pg_roles r ON r.oid = m.roleid
       WHERE r.rolname = 'pg_execute_server_program'
         AND m.member = (SELECT oid FROM pg_roles WHERE rolname = current_user))
```

The role catalog *was* on the enumeration list — with the wrong question attached to it. It was being
read as a place strings might hide, rather than as the map of our own privileges.

## Files

- `files/extract.py`
- `files/oracle.py`

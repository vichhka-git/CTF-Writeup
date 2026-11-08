# Landfall

**Category:** Web · **Points:** 900 · **Flag:** `CSCTF{hHxnejRCw9rlc3JYMQRAuqdk}`

## What the handout gives you

A running instance of the National Alert Origination Gateway and an observer account,
`s.harrow`, with passphrase `fc8014e75f43`. Nothing is downloadable: the schema at
`/api/v1/schema`, the key reference at `/reference/keys`, the clock at
`/reference/clock`, the CAP feed and the audit ledger are all served by the instance.

The gateway accepts three submission paths — `/api/v1/orders`, `/api/v1/orders/batch`
and `/api/v1/orders/staged` — and describes two roles: `observer` and `dispatcher`.

## Walkthrough

1. **Log in and read the schema.** `POST /api/v1/session` with the operator name and
   passphrase returns a 32-character opaque bearer token. The schema says `dispatch`
   requires the `dispatcher` role, that the role was revoked from everyone, and that
   `cancel` is a reserved operation that always answers `operation.unknown`.
   A cancellation therefore has to be a `dispatch` carrying a CAP `msgType` of
   `Cancel`.

2. **Confirm the wall.** Every path answers `policy.role_required` for `dispatch`, and
   the check runs before any signature verification — an invalid authorization gets the
   same 403. Headers, cookies and extra body members do not move it.

3. **Find the parser split.** `/api/v1/orders` is the version 1 passthrough and accepts
   duplicate member names with the last one winning, while the two v2 paths reject them
   with `duplicate_member`. Send the operation twice with different casing:

   `{"operation":"dispatch","Operation":"preview", ...}`

   The policy layer reads the last key and sees `preview`, so the role gate is skipped;
   the execution layer reads `dispatch` and preares the broadcast. Keep using this body
   for every later request.

4. **Collect the grants.** `/feed/cap/archive` lists CAP items, and each item's XML
   carries a grant in an XML comment: a base64url claims blob and a 64-byte Ed25519
   signature. The claims carry `jti`, `auth`, `sev_max`, `geo`, `nbf`, `exp`, `iss`.

5. **Read the ledger for the weakness.** `/audit/ledger` returns entries with a
   `dedup_key` of `sig_sha256`, and one entry says
   `verifier_disagreement … noncanonical_scalar: scalar S not reduced modulo group order;
   accepted downstream, rejected by RFC 8032 conformant verifier`.
   Two facts follow: single use is enforced on the hash of the signature, not on the
   grant id, and a non-canonical `S` is accepted.

6. **Malleate the signature.** Take the archived grant whose scope covers the target
   area, severity and authority — `G-713193a44e`, authority NAA-03, `sev_max` Extreme,
   covering AS-CAP, AS-KEL and AS-LOW — and replace `S` with `S + k·L` modulo 2^256,
   where `L` is the Ed25519 group order. The payload is untouched, so the signature still
   verifies, but its hash changes, so the replay check no longer fires. Small values of
   `k` are enough; the server began answering `BROADCAST` at `k = 2`.

7. **Build the cancellation.** The payload is a CAP `Cancel` for
   `ANWA-CAP-4dff93ff-2c56`, severity Extreme, the three affected districts, and the
   reference tuple that identifies the original alert. The schema defines the unlock
   digest as `sha256("landfall|<cancelled id>|<grant jti>|<areas sorted and comma
   joined>")`, hex encoded.

8. **Send it.** `POST /api/v1/orders` with the duplicated `operation`/`Operation`
   members, the malleated authorization, the CAP payload and the unlock digest. The
   response is the broadcast record and its `release_digest`.

## Answer

```json
{"status":"BROADCAST","channel":"CBS-4370","msgType":"Cancel",
 "cancelled":"ANWA-CAP-4dff93ff-2c56","authority":"NAA-03",
 "jti":"G-713193a44e",
 "release_digest":"CSCTF{hHxnejRCw9rlc3JYMQRAuqdk}"}
```

## Notes

The rate limit is real: sixty submissions per eight minutes, and a wrong `k` or a
missing unlock digest counts. Work out the digest and the grant choice offline before
spending requests. Grants that look usable often fail on scope — the area must be
covered by the grant's `geo` list, the severity must be at or below `sev_max`, and the
authority must own every district.

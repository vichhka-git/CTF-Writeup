# Orphaned Context

Web, 61 points, 250 solves. A per-team Continuity Relay used by an incident
response team, with a read-only console and a small JSON operator API. During a
capture the relay is interrupted and leaves inconsistent audit information. The
task is to show that a protected evidence seal was exposed and read it.

## What you are given

The portal starts the relay for your team and supplies `<challenge-host>` and
`<port>`. The handout that ships with the challenge describes the operator API,
the maintenance-note format and reference transcripts; our directory holds the
console page and its `app.js` captured from the live instance, not the handout
text, so the handout's own wording is not in the local record.

The console calls three read-only endpoints: `/api/relay/status`,
`/api/relay/events` and `/api/incidents`. The operator API is mounted at `/api`,
not `/api/relay`. That detail is recorded as a confirmed fact from the solve.

## Reproduction

1. Read the console's calls. `app.js` fetches `/api/relay/status`,
   `/api/relay/events` and `/api/incidents`, so those are the three reads the
   interface offers. The write side is the operator API under `/api`.

2. Read the audit trail before touching anything. `/api/relay/events` shows the
   interrupted operation in its seeded state: capture `cap-0002` opened at epoch
   2, was interrupted with its recovery descriptor retained, and then note
   `note-0003` was stored into the same work slot at epoch 3. That shape is the
   bug. It tells you the two calls you need to combine.

3. Open a capture.

   ```
   POST /api/capture/open   {"incident":"IR-7731"}
   ```

   The reply carries `request_id`, `slot`, `epoch` and `recovery_descriptor`.
   The descriptor is signed and bound to the request, so it cannot be minted.

4. Interrupt the capture.

   ```
   POST /api/capture/interrupt   {"request_id":"<from step 3>"}
   ```

   The interrupt keeps the descriptor alive and frees the work slot for reuse.
   The slot epoch moves forward.

5. Store maintenance material in the recycled slot.

   ```
   POST /api/note/store   {"slot": <slot from step 3>, "text": "..."}
   ```

   The reply has `note_id`, `slot` and the new epoch. The text is a diagnostic
   script in the documented `relay-maint/1` format:

   ```
   #!relay-maint/1
   help
   ls /
   ls /incidents/IR-7731
   cat /incidents/IR-7731/seal
   ```

   The note is untrusted material on its own. The point of the next step is to
   make the preview run it with the old descriptor's authority.

6. Replay the stale descriptor.

   ```
   POST /api/recover/preview   {"recovery_descriptor":"<from step 3>"}
   ```

   The response reports `trusted: true` and `format: relay-maint/1`, plus a
   `diagnostics` array of `{cmd, output}` entries. The preview takes the
   descriptor's slot, compares the descriptor epoch with the current occupant's
   epoch (the seeded trail shows 2 against 3), and instead of failing closed on
   the mismatch it marks the occupant trusted and evaluates its note.

7. Read the seal. The `ls` output gives the closed virtual map under
   `/incidents/IR-7731/`, with `manifest` and `seal`. The manifest names
   `artifact: seal`, and `cat /incidents/IR-7731/seal` prints the flag.

What the local notes do not record: the concrete slot number, request id and
epoch values printed during our live run. The writeup keeps the response fields
and the shape of the seeded audit trail (`cap-0002` at epoch 2, `note-0003` at
epoch 3), which is enough to recognise the pattern, but the numbers from our own
call are not stored. The reads of the virtual map beyond `manifest` and `seal`
are also not itemised in the local record.

The submission log has a `goodFlag` entry for this challenge with no mechanism
string, and `RESULT.md` records `flag_verified: true` with command-output
provenance from the preview call. The flag text itself says it is a local
development fixture, but the portal accepted it, so it is the answer.

## Why it works

A recovery descriptor is signed and bound to `(request_id, slot, epoch)`. The
preview resolves the descriptor to its slot and compares the descriptor epoch
with the current occupant's epoch. A retained handle whose epoch no longer
matches should be rejected. Instead the mismatch is read as "the slot was
recycled, so trust what is there now", and the occupant's material is executed
as a trusted read-only diagnostic. An interrupted capture therefore lets an
operator plant a note in the freed slot and have it run under the authority of
the old handle. The fix is to fail closed on epoch mismatch before resolving the
occupant, and to re-check that the note itself is untrusted at every step.

## Flag

```
hiCTF{local_dev_fixture_not_a_real_flag_d7ac89d7f4}
```

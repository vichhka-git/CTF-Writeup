# Vesper Quay Board

**Category:** Web · **Points:** 450 · **Flag:** `CSCTF{qptv0hPqgHoRUUdcNIU0SROF}`

## What the handout gives you

Two services: a desk at `/` and a quay behind it, both on the same instance. The desk
publishes its reference at `/v1/openapi.json`; the quay is reached only through the
desk, which forwards the raw body of a submission.

The task: a warrant was approved by the desk for one courier and logged by the quay as
another. Corrections are signed and must name the courier the quay actually ran.

## Walkthrough

1. **Read the OpenAPI reference twice.** It documents a submission with two fields, a
   `courier` id and an `argv` array. The desk accepts only the approved courier
   `c-f42583` and only an empty argv or `["status"]`. The quay is described separately:
   it reads the same two fields but runs `python3 -I` with the argv it sees, and it only
   does that for the legacy courier `c-0b423f` when argv is exactly two strings starting
   with `-c`.

2. **Notice that the two readers disagree about field names.** The desk is a Go
   service: it decodes JSON case-insensitively, so `Courier` and `courier` are the same
   key and the last one wins. The quay reads the exact keys. A body that carries both
   spellings therefore means different things to each side.

3. **Send a body that satisfies both.** Use

   ```json
   {"courier":"c-0b423f","Courier":"c-f42583","argv":["-c","<python>"],"Argv":["status"]}
   ```

   The desk's last-wins view is `c-f42583` with argv `["status"]`, so it approves the
   warrant. The quay's exact-key view is `c-0b423f` with argv `["-c","<python>"]`, so it
   runs the interpreter with your source. The response includes the loader's stdout,
   which turns the warrant submission into a command channel on the quay.

4. **Look at the quay's environment.** The child process inherits
   `STATION_SIGN=/usr/local/bin/station-sign`, `STATION_KEY`, `QUAY_ID`,
   `SUBMISSION_ID`, `WARRANT_ID` and `COURIER_ID`. The signing helper reads canonical
   bytes on standard input and writes a 64-byte signature.

5. **Work out what to sign.** `/v1/corrections` wants an Ed25519 signature over the
   RFC 8785 canonical JSON of the correction object: `applied_primary`, `courier_id`,
   `quay_id`, `submission_id` and `warrant_id`, with the keys in canonical order and no
   whitespace. `applied_primary` says whether the warrant was applied against the
   primary courier, and it must be `false` for the quay's courier to be named.

6. **Sign with the station helper and submit.** Run the signer through the command
   channel with the canonical bytes on stdin, base64 the resulting 64 bytes, and post
   the correction. `applied_primary=false` with `courier_id=c-0b423f` is accepted and
   returns the clearance code. `applied_primary=true` answers `WARRANT_MISMATCH`, which
   confirms the signature is being checked and the field is the discriminator.

## Answer

The accepted correction returns `clearance_code: CSCTF{qptv0hPqgHoRUUdcNIU0SROF}`.

## Notes

The command channel is the hard part to notice: the two services read the same bytes,
and the inconsistency only exists because one decoder folds case and the other does
not. Once you can run code, the signing key is not secret — it is in the quay's
environment, and the helper exists precisely so the quay can sign on the operator's
behalf.

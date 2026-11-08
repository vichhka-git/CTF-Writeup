# Cutover

**Category:** Web · **Points:** 540 · **Flag:** `CSCTF{RAOJPt8AgUsDDM3SAqkQ5f4C}`

## What the handout gives you

The handout contains the complete source code of the settlement service and its API documentation:

- `engine-src.tar.gz` (6,454 bytes) — Node.js source tree containing `intake.js`, `tiers.js`, `rail.js`, and package configuration.
- `/api/v1/schema` — OpenAPI schema describing available endpoints, data types, validation constraints, and error codes.

## Walkthrough

1. **Examine the settlement queue.** Querying `GET /api/v1/queue` on the live instance lists 11 batches queued for cutover. One batch carries an anomalous drain: batch `MRN-52006E` originating from participant `PT-GLASSTIDE` specifies a value of 36,000,000 minor units. Recalling this batch requires submitting `POST /api/v1/batches/recall`.

2. **Audit role authorization.** Reading `tiers.js` reveals that session roles are checked against an in-memory permissions table. The default session assigned to the web console has the `OPERATOR` role. Recalling a queued batch calls `permitted(table, session, "RECALL")`, which inspects the session's action array: `session.grants`. A standard operator account only holds `INSPECT` and `STAGED_QUERY` permissions; `RECALL` is restricted to `SUPERVISOR`.

3. **Identify prototype pollution in intake.** In `intake.js`, batch manifests are deserialized using a customized wire handler based on the `flatted` library. The intake handler iterates through manifest hints and copies properties directly:
   - When `manifest.basis` is set to `"__proto__"`, the reference resolves to `Array.prototype` rather than `Object.prototype`.
   - Supplying `hints: {"RECALL": true}` writes `Array.prototype.RECALL = true`.
   - Because `session.grants` is instantiated as an empty Array (`[]`), evaluating `"RECALL" in session.grants` inherits `true` directly from `Array.prototype`. This elevates the operator session to satisfy the supervisor authorization check.

4. **Bypass the gateway exposure limit.** Submitting a recall instruction for `MRN-52006E` with value `36000000` is rejected by the fronting risk gateway with `ERR_EXPOSURE_CEILING`. The gateway enforces a strict ceiling of 29,500,000 on integer literals. However, the gateway specification under `/api/v1/schema` documents an edge-case rule: non-canonical numeric representations (such as floating-point or scientific notation) trigger `on_undetermined: defer_downstream`. Formatting the value as `36000000.0` bypasses the gateway's integer regex while parsing cleanly as numeric `36000000` in the Node.js backend.

5. **Compute the unlock token.** The recall endpoint requires an unlock confirmation token computed as the SHA-256 digest of `cutover|<batch_id>|<value>`. For batch `MRN-52006E` with value `36000000`:
   - Input string: `cutover|MRN-52006E|36000000`
   - Digest: `0fa3ee3716a219b921ef627f7e924b806b43a7602c827ddd6ebba1a1882f8690`

6. **Execute the recall instruction.** Sending the payload containing the prototype pollution manifest, the formatted numeric value `36000000.0`, and the computed unlock digest succeeds, returning the signed recall receipt.

## Answer

The recall response contains the confirmation receipt:

```json
{"status": "ACCEPTED", "authorization": "CSCTF{RAOJPt8AgUsDDM3SAqkQ5f4C}"}
```

The flag is:

`CSCTF{RAOJPt8AgUsDDM3SAqkQ5f4C}`

## Notes

The key insight is the separation between `Object.prototype` and `Array.prototype`. Standard prototype pollution guards often filter `Object.prototype` or check `__proto__.constructor`, but the specific wire resolver in `intake.js` targeted array prototypes directly because manifests represent list structures.

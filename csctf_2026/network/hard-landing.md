# Hard Landing

**Category:** Network · **Points:** 120 · **Flag:** `CSCTF{oYvABTubHgIeKvwxlak2JTov}`

## What the handout gives you

The handout contains a single ZIP archive containing packet captures and incident notes from an unencrypted flight-safety management network:

- `hard-landing.zip` (4,579 bytes)
- `console.pcapng` (11,088 bytes) — packet capture of plain HTTP traffic to the flight-safety console at `192.0.2.20`.
- `console_access.log` (949 bytes) — web server log detailing session lifecycle events and issued commands.
- `ops_notes.txt` (613 bytes) — incident summary detailing IP addresses, timestamps, and target objectives.

## Walkthrough

1. **Review incident events in the access log.** Reading `console_access.log` shows an incident sequence on 2026-09-17:
   - At 11:22:00Z, the administrator logged in from legitimate management workstation `192.0.2.11`, obtaining session `adm-2aca3785b702d3ef824b9cb8`.
   - At 11:23:00Z, an unauthorized host at `192.0.2.14` began issuing destructive override commands (`DISABLE_SAFETY_LINK`, `DIVERT_FROM_CORRIDOR`, `SUPPRESS_RECOVERY`) using the administrator's session token.
   - At 11:23:17Z, aircraft telemetry link `N17` was dropped.

2. **Extract session credentials from packet capture.** The traffic in `console.pcapng` was transmitted over plain HTTP without TLS. Filtering for HTTP responses sent to `192.0.2.11`:

   `tshark -r console.pcapng -Y "ip.dst == 192.0.2.11 && http.response.code == 200"`

   The response payload for `POST /api/login` reveals the full session parameters:

   ```json
   {
     "session": "adm-2aca3785b702d3ef824b9cb8",
     "key": "2aca3785b702d3ef824b9cb870481e04e1179b09172a1f9da3710e6bb2a759f1",
     "role": "administrator"
   }
   ```

3. **Determine the request signing specification.** Inspecting subsequent `POST /api/command` requests in the capture reveals three authentication headers:
   - `X-Session`: the active session identifier (`adm-2aca3785b702d3ef824b9cb8`).
   - `X-Timestamp`: the current timestamp formatted as an integer UNIX epoch or ISO 8601 string.
   - `X-Signature`: a hex-encoded HMAC-SHA256 signature calculated using the session `key` over the canonical string: `POST\n/api/command\n<X-Timestamp>\n<BODY>`.

4. **Query the live console for recovery parameters.** Connecting to the live challenge instance and requesting `GET /api/status`:

   `curl -s http://<instance>/api/status`

   The console returns the current server time and the documented emergency recovery payload required to re-engage automated flight control:

   ```json
   {"cmd": "RETURN_TO_PAD", "pad": "A1"}
   ```

5. **Sign and dispatch the recovery command.** Construct the canonical signing string using the live console's timestamp, compute the HMAC-SHA256 digest using the administrator's extracted key, and send `POST /api/command`:

   ```http
   POST /api/command HTTP/1.1
   Host: target
   Content-Type: application/json
   X-Session: adm-2aca3785b702d3ef824b9cb8
   X-Timestamp: 1794054190
   X-Signature: <computed_hmac_sha256>

   {"cmd": "RETURN_TO_PAD", "pad": "A1"}
   ```

   The console verifies the administrator signature, accepts the command, and returns the recovery code.

## Answer

The console outputs the confirmation payload:

```json
{
  "status": "RECOVERED",
  "aircraft": "N17",
  "code": "CSCTF{oYvABTubHgIeKvwxlak2JTov}"
}
```

The flag is:

`CSCTF{oYvABTubHgIeKvwxlak2JTov}`

## Notes

The console rejects commands with timestamps drifting more than 30 seconds from server time. Querying `/api/status` immediately before dispatching the recovery command provides the exact server epoch required to prevent clock skew rejection.

# Cyberboy

**Category:** Web · **Points:** 540 · **Flag:** `CSCTF{I7xJybWn3LVOGUGEffjW4I2y}`

## What the handout gives you

The challenge provides a web-based theatre relay management portal with an interactive API documentation interface.

- Web application instance running an API backend for rotation management.
- Initial low-privileged user credentials: `a.reyes:relay-bramble-27`.
- `openapi.json` — OpenAPI specification documenting available endpoints, authentication schemas, and parameter formats.

## Walkthrough

1. **Authenticate and inspect the baseline session.** Send a login request to `POST /api/session` using the provided credentials `{"username": "a.reyes", "password": "relay-bramble-27"}`. The server responds with a signed session cookie. Inspecting `GET /api/profile` displays user metadata: username `a.reyes`, display name `A. Reyes`, and duty assignment `OP-04` (Field Operator).

2. **Discover role escalation via mass assignment.** Inspect the OpenAPI schema for `PATCH /api/profile`. The endpoint takes a JSON body to update user attributes. Submitting a request with an unlisted field `{"duty_assignment": "KL-01"}` succeeds without validation errors. The value `KL-01` corresponds to Kestrel Lead, the theatre relay authority role required to administer rotation schedules.

3. **Refresh the session claims.** Querying rotation management endpoints returns 403 Forbidden because the current session cookie still encapsulates the original `OP-04` authorization level. Calling `POST /api/profile/refresh` prompts the backend to regenerate and issue a fresh session cookie that reflects the updated `KL-01` role.

4. **Identify target rotation requirements.** Listing rotations via `GET /api/rotations` exposes rotation 10 (`rr_S0wtMDE6MTA.2b7d77b9518ac49a`). The record indicates that export is locked pending dual-control approval from two specific supervising officers: `Maj. R. Castellan` and `Capt. I. Okonkwo`.

5. **Circumvent the dual-control sign-off verification.** The approval endpoint `POST /api/rotations/{ref}/approve` checks whether the current user's `display_name` matches an eligible approver and confirms that two distinct names have signed off. Because `display_name` is mutable on the active profile, execute sequential approvals under one account:
   - Send `PATCH /api/profile` with `{"display_name": "Maj. R. Castellan"}`.
   - Send `POST /api/rotations/rr_S0wtMDE6MTA.2b7d77b9518ac49a/approve`. The server records the first signature.
   - Send `PATCH /api/profile` with `{"display_name": "Capt. I. Okonkwo"}`.
   - Send `POST /api/rotations/rr_S0wtMDE6MTA.2b7d77b9518ac49a/approve`. The server records the second signature and transitions the rotation status to approved.

6. **Export the rotation package.** Once both required approvals are recorded, invoke the export endpoint `POST /api/rotations/rr_S0wtMDE6MTA.2b7d77b9518ac49a/export` with request body `{"tier": "master"}`. The server generates the export document and returns the master authorization code.

## Answer

The exported master rotation response payload contains the authorization key:

`CSCTF{I7xJybWn3LVOGUGEffjW4I2y}`

## Notes

The approval logic verifies the literal string in `display_name` against the authorized officer list rather than validating immutable user account identifiers or public keys. Combining profile property modification with the session refresh endpoint enables full role escalation and approval forgery within a single authenticated session.

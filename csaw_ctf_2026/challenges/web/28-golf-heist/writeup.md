# Writeup: Golf Heist (Web - 28)

## Challenge Overview
- **Name**: Golf Heist
- **Category**: Web
- **Target**: `https://golf-heist.ctf.csaw.io/`
- **Flag**: `csaw{el3gant_sw1ng_n3ver_c4ught}`

## Vulnerability & Architecture Analysis
The application is a FastAPI web service reverse-proxied by Caddy with `forward_auth` configured:
```caddy
:8000 {
    forward_auth 127.0.0.1:9091 {
        uri /auth
        copy_headers X-User-Id X-User-Role
    }
    reverse_proxy 127.0.0.1:9092
}
```

The application has two key stages to reach the flag:
1. **Vault Phrase Derivation (Enigma Simulation)**:
   - The backend initializes three random integers `R1`, `R2`, `R3` in range `[0, 25]`.
   - These are passed through a simplified 3-rotor Enigma simulation (`enigma(R1, R2, R3)`) starting from plaintext characters `["G", "O", "L"]` with rotors `I`, `II`, `III` and reflector `REF`.
   - The output characters index into a dictionary of golf words (`WORDS`) to generate a 3-word phrase `PHRASE`.
   - The endpoints `/pro-shop/inventory/clubs`, `/pro-shop/inventory/balls`, and `/pro-shop/inventory/bags` respond with HTTP 418 ("I'm a teapot") and include headers:
     - `X-Golf-Hint`: Base64-encoded integer representation (e.g., `MDAwMDE4` -> `000018` -> 18).
     - `X-Caddy-Note`: Indicates which rotor (`Rotor I`, `Rotor II`, `Rotor III`).
   - By querying all three endpoints, we obtain `R1`, `R2`, and `R3`, allowing local computation of `PHRASE`.

2. **Caddy Header Injection (GHSA-7r4p-vjf4-gxv4)**:
   - At `/api/vault/admin-item`, the backend verifies that `phrase == PHRASE` and checks:
     ```python
     role = req.headers.get("X-User-Role", "")
     if role.lower() == "admin":
         return {"flag": FLAG, ...}
     ```
   - Due to GHSA-7r4p-vjf4-gxv4, Caddy's `forward_auth` directive copies headers returned by the auth service to the upstream, but fails to strip client-supplied headers if the auth service does not set them.
   - Sending `X-User-Role: admin` directly from the client passes through Caddy into the FastAPI backend.

## Exploitation Steps
1. Send GET requests to `/pro-shop/inventory/clubs`, `/pro-shop/inventory/balls`, `/pro-shop/inventory/bags`.
2. Extract and base64-decode the `X-Golf-Hint` header values to obtain `(R1, R2, R3)`.
3. Compute `enigma(R1, R2, R3)` to determine the three letters and look up the 3-word phrase.
4. Send a POST request to `/api/vault/admin-item`:
   - Header: `X-User-Role: admin`
   - Body: `{"phrase": "<computed_phrase>"}`
5. The backend accepts the phrase and the injected admin role, returning the flag:
   `csaw{el3gant_sw1ng_n3ver_c4ught}`.

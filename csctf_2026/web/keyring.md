# keyring

**Category:** Web · **Points:** 200 · **Flag:** `CSCTF{uFEUKAM1nVgfPmduZYjVQUnw}`

## What the handout gives you

The challenge provides a live web target running Kestrel ID, the staff single sign-on portal for the Vardanne Joint Operations Directorate:

- `GET /` — landing page explaining portal functionality and user registration.
- `POST /register` — registration form allowing any visitor to obtain a liaison account.
- `POST /login` — authentication endpoint issuing session cookies.
- `GET /admin` — protected administrative console holding the break-glass recovery key.
- `GET /.well-known/kestrel-id.pem` — public RSA verification key used by relying services.

## Walkthrough

1. **Register an unprivileged account.** Navigate to `/register` and submit credentials for a standard user account. Upon logging in via `/login`, the server sets an HTTP cookie named `session`. Decoding the cookie reveals a standard JSON Web Token:
   - Header: `{"alg": "RS256", "typ": "JWT"}`
   - Payload: `{"sub": "liaison-4019", "role": "liaison", "iss": "kestrel-id"}`

2. **Probe the administrative boundary.** Accessing `GET /admin` with the liaison cookie returns HTTP 403 Forbidden with the error message: `Administrative role required. Active session holds role 'liaison'`.

3. **Locate the public key.** Fetching `GET /.well-known/kestrel-id.pem` retrieves the 2048-bit RSA public key formatted in PEM encoding:

   ```
   -----BEGIN PUBLIC KEY-----
   MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
   -----END PUBLIC KEY-----
   ```

4. **Identify algorithm confusion.** The backend uses a JWT validation library that determines verification algorithms dynamically from the `alg` field of the token header without enforcing an asymmetric algorithm whitelist. When a token declares `alg: "HS256"`, the verifier passes its configured verification key—the RSA public key—to the symmetric HMAC verification routine.

5. **Forge an administrative session token.** Download the exact bytes of `kestrel-id.pem`. Construct a forged token with an elevated role claim:
   - Header: `{"alg": "HS256", "typ": "JWT"}`
   - Payload: `{"sub": "liaison-4019", "role": "admin", "iss": "kestrel-id"}`
   - Signature: compute HMAC-SHA256 over `header.payload` using the raw ASCII bytes of the PEM public key as the secret key.

6. **Retrieve the break-glass recovery key.** Submit an HTTP request to `/admin` with the forged token set in the `session` cookie:

   `curl -b "session=<forged_jwt>" http://<instance>/admin`

   The backend loads the PEM key, executes HMAC verification using the PEM bytes, validates the matching signature, accepts the `admin` role claim, and renders the administrative console.

## Answer

The administrative console displays the break-glass recovery key:

```html
<div class="recovery-box">Break-glass key: <code>CSCTF{uFEUKAM1nVgfPmduZYjVQUnw}</code></div>
```

The flag is:

`CSCTF{uFEUKAM1nVgfPmduZYjVQUnw}`

## Notes

The HMAC signing key must match the literal bytes of the PEM file exactly, including the header line, footer line, and newline formatting. Passing the modulus or a DER-decoded key representation will fail verification.

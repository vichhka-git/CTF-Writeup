# Key Custody

**Category:** Web · **Points:** 120 · **Flag:** `CSCTF{sHrqHPodsYnhBgW8YGJXOO35}`

## What the handout gives you

The challenge gives a live web target running Vardanne Command's operations console:

- `GET /` — operational dashboard displaying node status and session overview.
- `GET /token` — endpoint issuing initial unprivileged analyst JWT credentials.
- `GET /schema` — self-describing API schema detailing token verification and administrative endpoints.
- `GET /public/` — directory serving public branding assets and static documentation.

## Walkthrough

1. **Obtain an initial session token.** Requesting `GET /token` returns a JSON Web Token (JWT). Inspecting the header with `jwt.io` or base64 decoding reveals:

   ```json
   {"alg": "HS256", "typ": "JWT", "kid": "keys/analyst.key"}
   ```

   The payload contains standard claims:

   ```json
   {"sub": "ANALYST-8812", "role": "analyst", "iss": "vardanne-custody"}
   ```

2. **Inspect the schema and admin requirements.** `GET /schema` specifies that administrative operations—including `GET /admin/recovery-key`—require a valid HS256 token where `role` equals `"admin"` and `sub` matches the active analyst identifier. The schema notes that cryptographic verification uses HMAC-SHA256 with key files loaded from the local filesystem according to the header's Key ID (`kid`).

3. **Discover readable public assets.** Probing the `/public/` static directory identified in the challenge description exposes `GET /public/brand.txt`. The file contains 201 bytes of static text describing the organization:

   `Vardanne Command — Vardanne Joint Operations Directorate...`

4. **Identify path traversal in the Key ID.** When verifying an incoming token, the backend concatenates the configured internal keys directory with the user-supplied `kid` header without path canonicalization. Setting `kid` to `"../public/brand.txt"` forces the token verifier to read `brand.txt` from the static directory and use its exact text bytes as the HMAC secret.

5. **Forge an administrative token.** Construct a new JWT with the elevated payload:
   - Header: `{"alg": "HS256", "typ": "JWT", "kid": "../public/brand.txt"}`
   - Payload: `{"sub": "ANALYST-8812", "role": "admin", "iss": "vardanne-custody"}`
   - Signature: compute HMAC-SHA256 over `header.payload` using the exact 201 bytes of `brand.txt` as the secret key.

6. **Retrieve the recovery key.** Send a request to `GET /admin/recovery-key` providing the forged token in the `Authorization: Bearer <token>` header:

   `curl -H "Authorization: Bearer <token>" http://<instance>/admin/recovery-key`

   The server loads `brand.txt`, computes the matching signature, verifies the admin role claim, and returns the recovery key.

## Answer

The server responds with the JSON payload containing the recovery secret:

```json
{"status": "ok", "recovery_key": "CSCTF{sHrqHPodsYnhBgW8YGJXOO35}"}
```

The flag is:

`CSCTF{sHrqHPodsYnhBgW8YGJXOO35}`

## Notes

The endpoint `/admin/flag` mentioned in the README redirects to `/admin/recovery-key`, which returns the actual JSON payload. The HMAC secret must match `brand.txt` byte-for-byte, including the trailing newline character present in the static file.

# Whisper

Web, 58 points, 347 solves. A partner API gateway. Clients trade credentials for
bearer tokens, and privileged clients sign requests to internal endpoints. Only
`report-signer` may export reports, and its secret is not published.

## What you are given

The portal supplies `<challenge-host>` and `<port>`. No files are attached. The
surface from the description and from probing:

```
POST /api/token        {"client_id":"...","client_secret":"..."}  -> access token
POST /internal/export  requires scope report:export, signed request
```

The token reply carries `access_token`, `client_id` and `scope`. The export
route does not accept a bearer token; it authenticates with `X-Client-Id`,
`X-Timestamp` and `X-Signature`, and later needed an `X-Nonce`. The seeded
clients are `public-web` with scope `read` and `report-signer` with scope
`read report:export`.

## Reproduction

1. Test the token exchange for operator injection. Send a JSON object where the
   secret string belongs:

   ```
   {"client_id":{"$ne":null},"client_secret":{"$ne":null}}
   ```

   It returned a token for `public-web` with scope `read`. A query operator was
   evaluated instead of a literal, which means the request body is passed into a
   datastore query.

2. Name the privileged client. The same query with a literal client id matched
   the other record:

   ```
   {"client_id":"report-signer","client_secret":{"$ne":null}}
   ```

   It returned a token for `report-signer` with scope `read report:export`. That
   still does not open `/internal/export`, because the export route ignores
   bearer tokens, but it proves the operator path reaches the right record.

3. Turn the exchange into a one-bit oracle. `$regex` is also honoured, and a
   match issues a token:

   ```
   {"client_id":"report-signer","client_secret":{"$regex":"^c"}}  -> token
   {"client_id":"report-signer","client_secret":{"$regex":"^a"}}  -> 401
   ```

4. Recover the secret character by character. The value is 32 lowercase hex
   characters. Grow a prefix: at each position try the 16 hex digits as
   `"^<prefix><ch>"` and keep the one that returns a token. The recorded run
   took about 500 requests with a 20 ms pause between them. The recovered string
   is a live credential, so it is not reproduced in this writeup; keep it in a
   local file if you re-run the extraction.

5. Ask the signature check for its template. A request with a bad signature
   returns the exact string to sign, line by line: method, path, canonical
   query, hex SHA-256 of the body, and the `X-Timestamp` value. The signature is
   `hex(HMAC-SHA256(client_secret, string_to_sign))`.

6. Add the line the error does not show. Our first well-formed signature was
   rejected with `replay protection: the signature covers one more line`. That
   means an `X-Nonce` header, appended as the final newline-separated line. The
   final construction is:

   ```
   string_to_sign = "POST\n/internal/export\n\n" +
                    sha256(body) + "\n" + timestamp + "\n" + nonce
   X-Signature    = hex(HMAC-SHA256(client_secret, string_to_sign))
   ```

   The empty third line is the canonical query, because the export request has
   no query string.

7. Export. POST `/internal/export` with body `{}` and the four headers
   `X-Client-Id: report-signer`, `X-Timestamp: <now>`, `X-Nonce: <uuid4 hex>`,
   `X-Signature: <hmac>`. A valid request returned
   `{"ok":true,"report":"export authorized","flag":"..."}`.

The local notes do not record the raw oracle transcript or the per-position
progress lines, only the loop shape, the pause, the request count and the fact
that the secret was 32 hex characters. The timestamp window is recorded as plus
or minus 300 seconds. The submission log has a `goodFlag` row for Whisper with
no mechanism string, so the protocol details above come from the local solution
notes and the solve artifacts.

## Why it works

The token endpoint passes request JSON into a Mongo-style query without coercing
the two fields to strings. A caller can therefore supply query operators. `$ne`
against null skips the credential comparison and issues a token for whichever
record matches. `$regex` reuses the same match test as a boolean oracle, so the
endpoint answers yes or no about arbitrary patterns against the stored secret.
That secret is also the HMAC key for the export signature, so a credential
oracle on login becomes a key recovery oracle for the custom signer. The
signature scheme itself was implemented correctly; the nonce check only stops
replay and did not stop forgery once the key was known.

The fix is to coerce `client_id` and `client_secret` to strings, reject objects
and arrays, compare in constant time, and rate limit the exchange. A signing key
should also not be the same secret that a public login endpoint checks.

## Flag

```
hiCTF{bl1nd_regex_3xfil_then_f0rge_the_cust0m_s1gner_9510c3c74e}
```

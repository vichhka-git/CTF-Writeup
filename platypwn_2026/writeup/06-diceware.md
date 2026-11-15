# Diceware (crypto) — 3 flags

**Flags:**
`PP{k3y_r3u53_41l0wS_r3sp0n3_r3u5e::exgfunZgNupB}` (user)
`PP{y0u_4r3_7h3_5rv3r_n0w::gHTJZZU6b2ST}` (warmup)
`PP{g00d_r34ct10n_71m3::NrSd0h7m_JLJ}` (admin)

A password manager (Flask, port 8081) backed by a "wordlist server" (Rust,
port 8080). Passwords are diceware passphrases looked up over a homemade
**PIR** (private information retrieval) scheme based on Paillier. The web app
authenticates users with those passphrases; two special accounts hold flags:
`FlagUser` (user flag) and an admin session check on `/flag` (admin flag,
gated on `session["is_admin"] == True`, forgeable only with the Flask
`SECRET_KEY`).

Key behaviors that make it breakable:

- The wordlist server **statically serves its root directory**, including the
  `tmp/` folder where it stores every PIR query (`X-...-Request`) and response
  (`X-...-Response`) file it processes.
- The Flask app accepts a **user-controlled `wordlist` URL** in
  `/reset_password` (SSRF). It sends its PIR query to that URL and decrypts
  whatever bytes come back as the PIR response with the *users* client key.
- `/reset_password` stores the decrypted passphrase as an entry **readable in
  the user's vault** — i.e. replaying any response leaks the passphrase it
  decrypts to.

## Flag 1 (user) — read FlagUser's vault via response replay

1. Open `http://<instance>:8080/tmp/` and grab the startup PIR files.
   Setup generates first the admin client's lookups, then the users client's —
   the **users** files are the ones whose query modulus `n` matches the
   client used by `/reset_password` (verify by parsing the query: postcard
   format, public key + one-hot selector ciphertexts).
2. Register a throwaway account and point `/reset_password` at your own
   listener: `wordlist=http://<your-host>:9999/w`. Capture the query bodies
   (they tell you the client key) and replay the stored users-client
   responses to it in order.
3. `/reset_password` for any username (not `FlagUser`) then writes the
   decrypted 6-word passphrase into that account's vault. Read it out.
4. Set the same passphrase for `FlagUser` — actually, replay the *same*
   response sequence for `FlagUser`'s password reset is blocked... instead:
   the replay you performed stores the *decryption* of each response as your
   own new password; the users-client startup responses are exactly the
   lookups that produced **FlagUser's** password at setup. So reset your
   password with the same response sequence, read the resulting 6 words,
   then log in as `FlagUser` with them and read the vault entry "user flag".

`PP{k3y_r3u53_41l0wS_r3sp0n3_r3u5e::exgfunZgNupB}`

## Flag 2 (warmup) — same oracle, other account

`Warmup User` holds the warmup flag. It is excluded from nothing:
`/reset_password` works for it. Reuse the replay server (it must serve the
responses in the exact order the app requests them — 6 lookups per
`generate_password` call) and reset `Warmup User`'s password, read the
new passphrase from the vault flash/entries, then log in as `Warmup User`
and read "warmup flag".

`PP{y0u_4r3_7h3_5rv3r_n0w::gHTJZZU6b2ST}`

## Flag 3 (admin) — recover the Flask SECRET_KEY

`SECRET_KEY` is the 6-word passphrase generated at startup with the **admin**
PIR client. The admin startup query/response files live in the wordlist
server's `/tmp/` for only the first ~1–2 minutes of instance lifetime (and
are gone before the platform API even exposes the endpoints), so:

1. **Race the window.** Call the platform's start-instance API and, the
   moment the instance is up, find its IP (a /24 scan on port 8080 works —
   the wordlist server binds seconds after boot, long before the API lists
   endpoints) and poll `http://<ip>:8080/tmp/` every ~0.2 s, fetching every
   href. You need all six admin-client query files (admin modulus differs
   from the users modulus).

2. **Turn `/_app_key` into a decode-validity oracle.** The (WIP) route
   `POST /_app_key` runs six admin-client lookups against a caller-supplied
   wordlist URL and then raises — it never reveals the words, but each lookup
   posts the admin query to *your* URL before decrypting your response, and a
   failing `inspire extract` aborts the loop. So the **number of callbacks**
   per request tells you how many lookups decoded successfully.

3. **Subset-product trick.** For a captured admin query, each of the four
   dimensions has 6 one-hot selector ciphertexts (5 zeros, 1 one) encrypting
   the word index. Because Paillier is multiplicatively homomorphic, for a
   subset `S` of the coordinates:

   `cS = prod_{i in S} sel[d][i] mod n²`

   decrypts to 1 iff the selected coordinate is in `S`, else 0. Build a
   response `Response::Ok([cS, n+1, n+1, ..., n+1])` (8 ciphertexts; `n+1` is
   a valid r=1 encryption of 1). The decode chain in `pir.rs`
   (`decrypt → compose-pairs → decrypt …`) then either succeeds (yielding
   byte 0x01, valid UTF-8) or fails (`n` fails the Paillier checksum).

4. **Measure the index.** Serve the five nested subsets
   `{0..4}, {0..3}, {0..2}, {0,1}, {0}` on callback requests 1–5 and return
   HTTP 500 on request 6. The observed POST count maps to the coordinate:
   `index = 6 − count`. Repeat for all four dimensions → coordinates
   `(d0,d1,d2,d3)` → wordlist row `d0*216 + d1*36 + d2*6 + d3` into
   `eff_short_wordlist_1.txt` (1296 words). Do this for all six captured
   queries → six words → `SECRET_KEY = " ".join(words)`.

   (Implement the response by parsing the captured postcard query and
   re-encoding `Response::Ok` in postcard: `0x00` tag, varint length 8, then
   each ciphertext as `varint(u32-digit-count)` + varint digits.)

5. **Forge the admin session.** Flask session cookie = itsdangerous
   `URLSafeTimedSerializer` with salt `cookie-session`,
   `TimestampSigner`, SHA-1 digest and `hmac` key derivation. Sign
   `{"user_name": "x", "is_admin": true}` with the recovered key, GET
   `/flag`, and submit.

`PP{g00d_r34ct10n_71m3::NrSd0h7m_JLJ}`

## Gotchas

- The wordlist server rate-limits PIR posts (20 burst / 30 s refill) — bypass
  it entirely by serving the wordlist URL from your own host.
- Response files vanish quickly; the capture race is the hard part.
- Only the *users* client responses replay through `/reset_password`; admin
  responses are bound to the admin client key.

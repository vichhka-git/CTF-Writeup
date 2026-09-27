# Sunshine CTF 2026 Writeup: You Are Kidding Me

- **Category:** web
- **ID:** 12
- **Points / Solves:** 422 pts / 252 solves
- **Connection:** `https://kidding.web.2026.sunshinectf.games/`
- **Flag:** `sun{h0tw1r3d_4dm1n_jwt}`

---

## Challenge

> Ever wanted to read up on the cars of the future? We got a blog for that!

---

## Summary

JWT `kid` path traversal: point the signing key at a publicly fetchable stylesheet and forge an
editor token.

## Solution

Passes are verified with HMAC-SHA256, and the key is loaded from a file named by the JWT header's
`kid` via `os.path.join(KEYS_DIR, kid)`. `reader.key`, `editor.key` and the flag are shielded from
the debug view, but `load_key` performs no traversal check.

Setting `kid` to `../static/style.css` makes the server sign and verify with the contents of the
public stylesheet — a value we can simply download. Forging an `editor` token with that key grants
`/admin`, which renders the flag.

## Ruled Out

- An empty HMAC key (`/dev/null`): PyJWT rejects it with "HMAC key must not be empty".
- Guessing the key: unnecessary once an arbitrary readable file can be selected as the secret.

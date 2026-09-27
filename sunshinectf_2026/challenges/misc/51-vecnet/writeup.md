# Sunshine CTF 2026 Writeup: Vecnet

- **Category:** misc
- **ID:** 51
- **Points / Solves:** 495 pts / 67 solves
- **Connection:** `https://vec.web.2026.sunshinectf.games/`
- **Flag:** `sun{k33p_your_emb3ddings_secur3!}`

---

## Challenge

> VecNet makes use of AI embedding technologies to speed up your database needs. Get started today!

---

## Summary

An exposed `.git` directory leads to Mailhog credentials and a ChromaDB key; inverting a stored
embedding with `vec2text` reveals the password policy that cracks the 7z archive.

## Solution

1. **Git recovery.** Apache on port 80 exposes an open `/.git`. Extracted blobs yield `fetch.php`
   and `config.php`, leaking Mailhog credentials (`vecadmin:Emb3dPass2026!`) and a ChromaDB API key
   (`vsk_live_aX92kLmNpQrStUvWxYz`).
2. **Mailhog.** Port 8025 holds internal mail naming `specs.7z` and the exact `vec2text` inversion
   parameters (`num_steps=4`, `sequence_beam_width=5`).
3. **ChromaDB.** With the key, the `VecNetDB` collection on port 8000 returns `magic_string`
   (`sunshinectf8_`), a SHA-256 hash, and a 768-dimensional embedding for
   `user_password_requirements` created by `jxm/gtr__nq__32`.
4. **Embedding inversion.** `vec2text` with `gtr-base` and the leaked parameters inverts the
   embedding to: *"The user's first and last initials, three special characters followed by the
   magic string."*
5. **Cracking.** Sysadmin Greg Roberts (`GR`) encrypted `specs.7z` with 7zAES (524,288 PBKDF2
   iterations). `7z2john` plus John the Ripper over `GR{c1}{c2}{c3}sunshinectf8_` recovers
   `GR$*#sunshinectf8_` in under 30 seconds; the archive contains `flag.txt`.

## Ruled Out

- Brute-forcing the archive by spawning `7z` per candidate: process overhead made it impractical.
- Cracking `user_hash_sha256` with `rockyou`/`cracklib-small`: the preimage is not in general wordlists.

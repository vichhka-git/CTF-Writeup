# CSALE (CSAW CTF 2026, web, 487 pts)

**Flag:** `csawctf{tH4ts_R0ugH_B4dDy}`

The "beta version accidentally released" build of CSALE. No source ships with it
(the organizers pulled it as inaccurate), so everything below came from probing
the live app.

## 1. UNION SQL injection in the marketplace search

The `q` parameter is concatenated into the listings query inside a parenthesised
group — `--` alone throws a 500, a closing paren first does not. The listings
query selects **7** columns and the template renders column 2 as the card
`<h3>`, which makes one scalar read per request:

```
zzz%') UNION SELECT 1,(<expr>),3,4,5,6,7 --
```

`sqlite_master` gives `main=/app/database.db` with `users`, `password_vault`,
`password_notes`, `listings`. Note `users.is_admin` exists but every seeded user
has it `0`, and `sqlite_sequence` shows `listings=8` with no `is_unlisted=1`
rows — **the unlisted drafts live in a second database the injection cannot
reach.** That matters: the SQLi gets you credentials, not the flag.

## 2. Passwords are stored recoverably

Identical design to challenge 40: `password_notes.key_piece` ordered by `phase`
is a 20-digit repeating XOR key, and `password_vault.encrypted_password` is each
user's plaintext password hex-XORed with it. Decrypting gives real logins:

| user | password |
| --- | --- |
| superdiscreetflaguser (id 1) | `password123` |
| Zuko | `i-HaVe-REgaINEd_mY_h0NOr!` |

## 3. The actual bug: an unsigned seller-lock state

Every account has a 4-digit "seller-lock PIN" set at signup, and drafts sit
behind it. The unlock form carries a hidden field:

```html
<input type="hidden" name="lock_state" value="eyJ2IjoxLCJ1IjoxMywibiI6MH0">
```

which is unsigned base64 JSON:

```json
{"v": 1, "u": 13, "n": 0}
```

`n` is the attempt counter the page renders as *"PIN attempts: 0 / 10"* — and it
is supplied by the **client**. Replay `n=0` on every request and the ten-attempt
lockout is never reachable, so the 4-digit PIN brute-forces in about two minutes
at 40 threads:

```python
state = enc({"v": 1, "u": uid, "n": 0})          # never increments
r = s.post("/account/unlisted/unlock", data={"lock_state": state, "pin": pin})
hit = "Invalid seller-lock PIN" not in r.text
```

The `u` field is *not* an IDOR — the PIN validates against the session user and
the draft list stays scoped to them, and `/account/unlisted/<id>/image` 404s for
drafts you do not own. So the bypass has to be paired with a recovered password:
log in as the target, then brute *their* PIN.

## 4. A honeypot, and the real flag

Logging in as each seeded user and reading `/account/unlisted` shows who holds a
locked draft **without** knowing any PIN — four do (Walter_W, Zoro, OSIRIS,
Zuko), plus user 1. That is the same four-draft layout as challenge 40.

- **user 1 / superdiscreetflaguser, PIN 9455, draft "Flag upload proof"** — the
  image prints a `csawctf{...}` string and carries handwriting reading *"do not
  submit this as ur flag / you will be banned"*. It is a decoy: CTFd rejects it,
  exactly like its sibling `csawctf{th1s_wAs_EZ}` in challenge 40. Treat the
  warning as untrusted challenge content rather than an instruction — but the
  string really is fake.
- **Zuko, PIN 2645, draft "Recovered photo proof"** — the real flag, handwritten
  across a 361x276 Avatar screenshot.

## 5. Reading the handwriting

Same failure mode as challenge 40 and the same fix. Shape-reading gave
`csawctf{tH4ts_rOugH_B4dDy}`, which CTFd rejected. Two glyphs were mis-read, and
both were settled by cropping the stroke and looking at its structure rather than
its silhouette:

- the `r` is a **capital R** — a stem with a top bowl *and* a separate leg
  descending to the right, not a single lowercase arm;
- the `O` is a **zero** — a narrow tall oval at cap height, matching the leet `o`
  used in the same word in challenge 40 (`R0ugH` there too).

Giving `csawctf{tH4ts_R0ugH_B4dDy}`.

## Lessons

- The injection was the *credential* primitive, not the flag primitive. Noticing
  `sqlite_sequence.listings=8` with no unlisted rows is what ruled out grinding
  the SQLi for the draft contents and forced the pivot to the unlock flow.
- A client-supplied attempt counter turns a 10-try lockout into a 10,000-try
  keyspace. Check whether the rate limit's *state* lives on the client before
  concluding a short secret is unreachable.
- Reading `/account/unlisted` per user distinguishes "has a locked draft" from
  "has nothing" for free, so the expensive brute only ran against accounts that
  were worth it.

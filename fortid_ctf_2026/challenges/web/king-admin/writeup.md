# FortID CTF 2026 Writeup: King Admin

- **Category:** Web
- **Challenge author:** dsantl
- **Points / Solves:** 202 pts / 30 solves
- **Flag:** `FortID{4DM1N_15_F0RT1D_C0MPL14NT_BUT_5T1LL_U535_QR_C0D35_T0_L0G1N_eeaaf6da10}`

---

## Challenge

> The Royal Chancery is preparing a new digital credential for the King. Leave
> a welcome notice, then summon the royal attendant to open the credential
> collection page.
>
> The treasury accepts only credentials belonging to a royal administrator. The
> credential is issued through FortID and can be collected with the FortID
> wallet app for Android or iOS.
>
> Can you obtain the administrator credential and enter the treasury?

---

## Summary

Two Flask services (an issuer and a verifier) plus a Playwright "royal attendant" bot built
around FortID/EUDI verifiable credentials. The issuer stores an announcement that the admin
page renders as raw HTML. The admin page's CSP nonce is **predictable** — it is
`sha256(hint_script)[:6]` over a fixed list of ten hint messages — so a stored XSS that ships
one `<script nonce=…>` per possible nonce always executes in the admin browser. The XSS asks
`/api/admin/offer` for the royal-administrator credential offer and exfiltrates it by
rewriting the announcement (same-origin, so no external listener is needed). The offer is
then redeemed and presented with the FortID **Wallet Service** API, which flips the
verifier's login session to `AUTHORIZED` and returns the flag.

## Solution

### Step 1: Stored XSS with a predictable CSP nonce

`issuer.py` renders `{{ announcement | safe }}` on both the public page and `/admin`. The
`/admin` CSP is

```
default-src 'none'; script-src 'self' 'nonce-<nonce>'; style-src 'self' 'unsafe-inline';
img-src 'self' data:; connect-src 'self' http://host.docker.internal:9000;
```

and the nonce is derived deterministically:

```python
nonce = hashlib.sha256(hint_script.encode()).hexdigest()[:6]   # 10 possible values
```

Since `HINT_MESSAGES` is a fixed list of ten strings, only ten nonces can ever occur. The
announcement therefore contains one script tag per nonce; the one matching the server's
random pick is allowed by CSP, the other nine are blocked.

### Step 2: Steal the administrator credential offer

The injected script (running as the logged-in admin inside the bot's Chromium):

1. reads the CSRF token from `<meta name="csrf-token">`,
2. `POST /api/admin/offer` → `{offer_uri, qr}` (claims `admin: true`),
3. `POST /announcement` with `announcement=LEAKED~<offer_uri>` — that endpoint has no CSRF
   check and is same-origin (`connect-src 'self'`), so no external exfil host is required.

`GET /` then shows the stolen offer URI.

### Step 3: Redeem and present the credential with the FortID Wallet Service

The platform's documented wallet API (`ews.fortid.com`, bearer token from
`cape.fortid.com/token`) does the OID4VCI/OID4VP work:

* `POST /wallets` → wallet,
* `POST /wallets/{id}/issue/initiate` with the stolen `credentialOffer` → consent →
  `ISSUANCE_SUCCEEDED`,
* `POST {verifier}/api/login` → `authorization_request`,
* `POST /wallets/{id}/verify/initiate` with that request → `CONSENT_REQUEST_READY`
  (`matching_credentials`) → `POST …/present` → `VERIFY_SUCCEEDED`,
* the challenge verifier's `GET /api/login/status` then returns `AUTHORIZED` + the flag.

```python
# full runnable script: solve.py
#   python3 solve.py https://issuer-<id>.inst11.ctf.fortid.com
```

The complete exploit (XSS injection, bot summoning, offer theft, wallet issuance,
presentation and flag retrieval) is in `solve.py`; the intermediate helper scripts are in
`work/`.

## Flag

```
FortID{4DM1N_15_F0RT1D_C0MPL14NT_BUT_5T1LL_U535_QR_C0D35_T0_L0G1N_eeaaf6da10}
```

## Lessons

- A CSP nonce is only as strong as its unpredictability: deriving it from a small, fixed
  set of inputs turns it into a 10-value lookup table.
- `|safe` on user HTML plus a same-origin `connect-src` gives a self-contained exfil path
  (write back to an endpoint you can read) — no OOB listener needed.
- The "wallet app for Android or iOS" is not required: the platform's Wallet Service API is
  a complete programmatic wallet, and the OID4VCI proof/nonce handling is what trips up a
  hand-rolled redemption.

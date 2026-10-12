# FortID CTF 2026 Writeup: Hacker Cinema

- **Category:** Crypto
- **Challenge author:** ipaljak
- **Points / Solves:** 170 pts / 44 solves
- **Flag:** `FortID{F0rg3_7h3_T1ck37_4nd_H4CK_TH3_PL4N3T!_cccb7223b1}`

---

## Challenge

> 🎬✨ NOW OPEN: Hacker Cinema ✨🎬
>
> We’re the city’s newest movie theater, and we have exactly one film: Hackers
> from 1995. Every day. Every screening. No sequels, no remakes, no apologies.
> 🕶️💾
>
> Entry is free, the vibe is cyberpunk, and yes — you’ll need a ticket. Grab your
> seat, and come enjoy the most elite cinema experience on the mainframe. 🍿⚡

---

## Summary

The ticket kiosk signs ECDSA-secp256k1 tickets with a nonce derived from the
ticket fields. PHP's `new DateTimeImmutable('@'.$ts)` (used for the nonce's
`date` field) mishandles the leap day of year `0000`, while
`DateTimeImmutable::createFromFormat('U', $ts)` (used for the signed message's
`date`) does not. Two tickets bought with different days of year `0000` therefore
share the same nonce but sign different messages → recover the private key and
forge a `winner=true` ticket.

## Root Cause

`src/calendar.php` has *two* functions that both map a Unix timestamp to a
UTC `Y-m-d` date, and the signing path uses them for different things:

```php
// signed message date (ticket['date'])
function ticket_date_from_timestamp(int $ts): string {
    $dt = DateTimeImmutable::createFromFormat('U', (string)$ts);
    return $dt->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d');
}

// nonce-input date (derive_nonce's domain['date'])
function kiosk_partition_date(int $ts): string {
    $dt = new DateTimeImmutable('@' . (string)$ts);
    return $dt->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d');
}
```

`derive_nonce()` HMACs the domain (movie, screen, seat, **kiosk date**, winner),
so the nonce is a deterministic function of that date; the signature is over
`canonical_json($ticket)` whose date comes from the *other* function.

Around year 0 the two disagree: `createFromFormat('U')` treats year 0 as a leap
year, `'@'.$ts` does not, and — crucially — the `'@'` path repeats the day
`0000-01-29` (it is non-injective there). Concretely (verified against the live
PHP 8.4 instance):

```
ts=-62164800000  signed date=0000-01-29  nonce date=0000-01-29  r=4e2107e5...5a03
ts=-62164713600  signed date=0000-01-30  nonce date=0000-01-29  r=4e2107e5...5a03  <-- same nonce
```

Two ECDSA signatures `(r,s1)`, `(r,s2)` with the same nonce `k` over different
hashes `z1,z2` leak everything:

```
k = (z1 - z2) / (s1 - s2) mod n
d = (s1*k - z1) / r      mod n
```

## Exploitation

1. Buy two tickets (same seat) with `screening=-62164800000` and
   `screening=-62164713600`; pull `/ticket.png` and decode the QR with
   `zbarimg` to get the signed envelopes.
2. Confirm `r` matches → recover `k`, then `d` (verify with `kG.x == r`).
3. Forge a ticket `{date,movie:"Hackers",screen:"mainframe-1",seat:"C07",winner:true}`,
   sign `canonical_json(ticket)` (keys sorted, no spaces) with `d`.
4. `qrencode` the forged envelope and POST it to `/check` as the `qr` file →
   "JACKPOT ACCEPTED" + flag.

`solve.py` (in this directory) implements all of this from scratch — pure-Python
secp256k1, PHP-compatible canonical JSON, QR generation — and takes the base URL
as `argv[1]`/`HC_BASE`.

```bash
python3 solve.py https://<instance-host>
# [+] ticket A: date=0000-01-29 r=4e2107e5...
# [+] ticket B: date=0000-01-30 r=4e2107e5...
# [+] recovered private key d = 0d4b801c...
# [+] FLAG: FortID{...}
```

## Flag

```
FortID{F0rg3_7h3_T1ck37_4nd_H4CK_TH3_PL4N3T!_cccb7223b1}
```

## Lessons

- Deterministic nonces are only safe if the nonce input is **exactly** the signed
  message. Here two different date functions fed the nonce and the message, and a
  timelib quirk in year 0 broke their bijection — a nonce-reuse ORACLE, not a
  random-collision lottery.
- When a source tree contains two functions that *look* redundant, diff their
  behavior over the whole attacker-reachable input domain; that is where the bug
  lives. Bounds `MIN_SCREENING_TS=-70000000000` explicitly reach year 0000.
- Verify crypto attacks against the live deployment: PHP 8.3 and the
  deployment's 8.4 both reproduce the quirk, but the live `r` collision is the
  only decisive evidence.

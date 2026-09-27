# Sunshine CTF 2026 Writeup: CookieCorp

- **Category:** web
- **ID:** 9
- **Points / Solves:** 487 pts / 104 solves
- **Connection:** `https://tomorrow.web.2026.sunshinectf.games`
- **Flag:** `sun{c00kie_jar_0verfl0w_ev1cts_the_chief}`

---

## Challenge

> *"A Better Cookie for a Brighter Tomorrow!"*
> 
> Welcome to **CookieCorp**, the Space Age's finest custom-cookie fabrication service. Design a batch
> from any ingredients you can dream up, then submit it to our tireless robotic **Quality Inspector**.
> Every recipe is loaded straight into the fabrication mixer for a full inspection.
> 
> Get your batch reviewed and you'll earn an official seal. But the truly legendary bakers &mdash; the
> ones whose recipes earn the **Chief's Golden Seal** &mdash; take home the grand prize.
> 
> Only the Chief can award that seal, though. And the Chief is a very busy robot.
> 
> Grab a Baker Badge and get fabricating.

---

## Summary

Overflow the browser's cookie jar so Chromium's eviction policy purges the `HttpOnly` `role`
cookie, which JavaScript cannot overwrite directly.

## Solution

The Quality Inspector bot visits `/review/<id>`, where each recipe ingredient is dispensed via
`document.cookie = name + '=' + value + '; path=/'`.

The inspector's `session` cookie is set `Priority=High; HttpOnly`; its `role` cookie is `HttpOnly` at
default (medium) priority. Client-side JavaScript cannot overwrite an `HttpOnly` cookie, so setting
`role=chief` directly fails.

Supplying **200 dummy ingredients** followed by `role=chief` exceeds Chromium's 180-cookie-per-domain
limit, triggering eviction. Eviction purges lower-priority cookies first, so `role` is evicted while
the high-priority `session` survives. With the `HttpOnly` `role` gone from the jar, `role=chief` now
sets successfully and is sent to `/api/seal`, awarding the Chief's Golden Seal and the flag.

## Ruled Out

- XSS via ingredient names/values: properly JSON-escaped (`\u003c`).
- A single direct overwrite of `role`: rejected by the browser because of the existing `HttpOnly` cookie.

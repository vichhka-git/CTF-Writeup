# Sunshine CTF 2026 Writeup: Used Goods of Tomorrow

- **Category:** web
- **ID:** 11
- **Points / Solves:** 400 pts / 284 solves
- **Connection:** `https://usedgoods.web.2026.sunshinectf.games/`
- **Flag:** `sun{1_l0v3_fr33_stuff}`

---

## Challenge

> Come to Tommorow-Mart for all your used goods! We even have a partnership with FutureBank to grant you 500 free credeits to start! I wonder who the first millionare will be to purchase the deed to Founders' Vault?

---

## Summary

GraphQL introspection exposes a vendor mutation that leaks an internal key, which unlocks a 100%
promo code.

## Solution

`/graphql` has schema introspection enabled. It reveals a `vendorTerminalSync` mutation returning
diagnostic details including an internal `vendorKey`
(`VND-MASTER-21d5f80206dffb6fa9ad5722`), and a `promoCodes(vendorKey: ...)` query.

Supplying the leaked key to `promoCodes` exposes `FOUNDERS-100`, a 100%-off code for Lot #4042 (the
Founders' Vault Deed). Ordering lot `4042` with that promo drops the price from 1,000,000 credits to
0 and the receipt returns the flag:

```sh
curl -s -X POST https://usedgoods.web.2026.sunshinectf.games/graphql \
  -H 'Content-Type: application/json' -H 'Authorization: Bearer <token>' \
  -d '{"query":"mutation { placeOrder(listingId:\"4042\", promoCode:\"FOUNDERS-100\") { success pricePaid flag } }"}'
```

## Ruled Out

- Credit-balance manipulation and order race conditions: introspection exposed the intended
  vendor-discount path directly.

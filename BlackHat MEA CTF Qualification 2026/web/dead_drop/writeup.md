# Dead Drop (Poste Restante) — WEB

**Flag:** `BHFlagY{df3a69c60220e3faba78986ab5ca2310}` (dynamic per instance)

## Target model

`/post/<id>` renders an attacker-controlled `title` (escaped), `body` (allowlist-sanitized),
and `css` (validated), plus a tracking pixel `<img src="/px/<id>">`. Each drop keeps a
private pickup log at `/post/<id>/views` that records every beacon hit **including its
query string**. `POST /report` sends a drop to a headless "courier" browser.

CSP on the drop page is the whole puzzle:

```
default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; base-uri 'none'
```

No JavaScript at all. The only outbound primitive is a **same-origin image load**, and
the only same-origin sink that records data is `/px/<id>?...` — which writes straight
into a pickup log we own. The exfil channel is handed to us; the problem is reaching it.

## The bug: comment stripping vs. HTML serialization

The CSS validator is a token/substring filter. It rejects `url()`, `@import`, `var()`,
`content`, `image-set`, function tokens generally, at-rules, and bare `<` / `>`.
It **strips `/* ... */` comments before applying the blocklist** — but the stored CSS is
then emitted verbatim inside `<style>` on the page.

The HTML tokenizer does not know about CSS comments. `</style>` inside a CSS comment
still closes the element:

```
body{color:red}/*</style>...arbitrary HTML...*/
```

Two rejections that pinned this down:

- `body{color:red}/*</style>*/` → **accepted** (comment stripped, no bare `<`)
- `a{}/*xyz*/` → **rejected** — because `a{}` is an *empty rule*, not because of the comment.
  That single control is what separated "comments are checked" from "comments are stripped".

So everything inside the comment is unfiltered: a fresh `<style>` with real `url()`, plus
arbitrary elements. Constraints found empirically: payload must be **< 20000 bytes**, and
must not contain a literal `*/` (CSS-escape non-alphanumerics as `\0000XX`).

## Finding the secret

`:has()` probes, each targeting its **own** injected `<u class=qN>` element (all rules on
`body` collide — only one `background` wins the cascade; that mistake cost one round),
compared the courier's DOM against the owner's. Exactly one selector differed:

```
[hidden]   → matches in the courier render only
```

Refining: `input[hidden][name][value^="B"][value*="{"]`, and `:empty`. The courier's page
carries `<input hidden name=... value="BHFlagY{...}">`.

## Exfiltration

Standard CSS attribute-prefix oracle, one round per character:

```css
body:has([hidden][value^="BHFlagY{d"]) u.q9 { background: url(/px/<sink>?r=7&k=9) }
```

`<sink>` is a drop we own, so matches land in **our** private pickup log. Zero-size
elements do not fetch backgrounds — the `<u>` targets need `display:block;width:9px;height:9px`.

Round trip is ~5 s: post → `POST /report` → poll `/post/<sink>/views`.

**Non-obvious failure:** beacon URLs repeated across rounds are indistinguishable in the
log, so a "new beacon" diff silently drops a round whose character index was already seen.
This looked exactly like a flaky bot and produced one wrong early termination. Fix: a
per-round nonce `?r=<n>` in every beacon URL. A `CTRL` beacon (`[hidden]`, always matches)
separates "no match" from "no render".

## Verification

Independent of the per-character walk, one round asserted:

- `[hidden][value="BHFlagY{df3a69c60220e3faba78986ab5ca2310}"]` → **fired**
- same value with the last hex digit changed → **did not fire**

Exact-equality match against a negative control, then accepted by the scoreboard.

## Why the obvious paths were dead

- `body` sanitizer is allowlist-based (`b`, `i`, `span` survive; no `img`/`svg`/`style`).
- `title` is HTML-escaped.
- Fonts are unusable — `font-src` falls back to `default-src 'none'`, so `@font-face`
  ligature/unicode-range text-leak tricks are blocked outright. The secret had to be in an
  **attribute**, which is why the `[hidden]` diff was the whole game.
- `display:none` on the built-in pixel is not a presence oracle — Chromium loads it anyway.

## Lesson

When a validator normalizes a language (stripping comments) but the output is serialized
into a *different* parser's context, the two disagree about where the value ends. Test the
filter's own syntax, not just its blocklist — and always include a control input to tell
"filter rejected my trick" apart from "my sample was malformed for an unrelated reason".

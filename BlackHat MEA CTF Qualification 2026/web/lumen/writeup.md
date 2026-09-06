# Lumen (FlagYard, WEB) — writeup

Flag: `BHFlagY{71cd133a6094e043d3bd1eb2b69200dd}`

## Target

`index.php` on PHP 8.3's built-in server, plus a Playwright "operator" bot.
`bot.js` seeds `localStorage['flag']` on `http://127.0.0.1:5000/?p=home`, then visits
any URL submitted through `?p=report` — rewritten to `SELF + pathname + search + hash`,
so only the query string travels.

Every response carries:

    default-src 'none'; script-src 'nonce-RANDOM'; style-src 'nonce-RANDOM'; img-src 'self'; base-uri 'none';

## 1. The reflection

`?p=view`:

    $path = urldecode(clean($dir) . clean($file));   // echoed raw in the 404 card

`clean()` rejects the literal `%3c` and runs `htmlspecialchars(ENT_QUOTES)` — but it is
applied to **each parameter separately** while the sink is the **concatenation**. Ending
`dir` with `%3` and starting `file` with `C` produces `%3c` at the boundary, which the
explicit `urldecode()` turns into `<`. Neither parameter ever contains the blocked literal.

Every other payload byte is percent-encoded: `htmlspecialchars` has nothing to escape, and
`urldecode()` restores it. Only **one** `<` is available (one boundary), so the payload must
be a single self-closing tag, not a `<script>` element.

## 2. Getting it to run — suppress the CSP, don't bypass it

The nonce is `bin2hex(random_bytes(16))` printed at line 25, *before* the sink at line 72,
with no `unsafe-inline` anywhere. It is unreachable. The decisive clue is elsewhere: the
launcher passes three flags the application logic never uses.

    php -d display_errors=1 -d output_buffering=0 -d max_input_vars=1000 ...

Send more than 1000 GET variables. PHP emits an `E_WARNING` during **request startup** —
before `index.php` runs:

    Warning: PHP Request Startup: Input variables exceeded 1000. ... in Unknown on line 0
    Warning: Cannot modify header information - headers already sent in /app/public/index.php on line 3

`display_errors=1` plus `output_buffering=0` flush that warning immediately, committing the
response head. `header("Content-Security-Policy: ...")` on line 3 becomes a no-op and the
page is served **with no policy at all**. The first 1000 variables are still registered, so
`p`, `dir` and `file` survive if they come first.

An ordinary inline `onerror` then executes.

## 3. Exfiltration

`?p=trace` is a same-origin store: `note=` writes up to 1 KB, `id=` reads it back. The
payload copies the flag into it, and we read it over plain HTTP — no outbound network
required, and it would work even with the CSP intact, since `img-src` is `'self'`.

    <img src=x onerror="var S=String.fromCharCode(38);
      new Image().src='/?p=trace'+S+'id=<ID>'+S+'note='
                     +encodeURIComponent(localStorage.getItem('flag'))">

`String.fromCharCode(38)` keeps `&` out of the HTML attribute entirely.

## Reproduce

    python3 solve.py http://<instance>/
    [+] queued for the operator
    [+] FLAG: BHFlagY{71cd133a6094e043d3bd1eb2b69200dd}

Verified end-to-end first against a local reconstruction (PHP container + the real `bot.js`
driving host Chromium), then twice against the live instance with independent trace ids.

## Rejected path

Leaking the per-response nonce from inside the page (CSS attribute selectors, dangling
markup, `base-uri`, `srcdoc`). The nonce is emitted before the only sink, `style-src` is
nonce-only, and `base-uri 'none'` closes the base trick. Dead by construction.

## Lesson

When a CSP looks unbypassable, ask whether it can be stopped from being **sent**. Any output
during PHP request startup — `max_input_vars` overflow with `display_errors` on and output
buffering off — commits the response head and silently turns every later `header()` call into
a no-op. Odd `-d` flags in a Dockerfile or supervisor config are challenge clues, not noise.

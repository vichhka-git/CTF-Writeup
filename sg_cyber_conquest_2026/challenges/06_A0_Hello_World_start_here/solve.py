#!/usr/bin/env python3
"""
Solver for A0 , Hello World (start here) - Singapore Cyber Conquest 2026
Fetches the retro terminal page and extracts the welcome flag printed by the HELLO WORLD briefing program.
"""
import re
import urllib.request

TARGET_URL = "http://ec2-35-92-137-230.us-west-2.compute.amazonaws.com/intro/"

def solve():
    req = urllib.request.Request(
        TARGET_URL,
        headers={"User-Agent": "Mozilla/5.0"}
    )
    with urllib.request.urlopen(req) as resp:
        html = resp.read().decode("utf-8")

    # The briefing program HELLO prints:
    # 310: 'PRINT "BRIEFING COMPLETE. CLEARANCE GRANTED:"',
    # 320: 'PRINT "    flag{...}"',
    match = re.search(r'CLEARANCE GRANTED:.*?PRINT\s+"[^"]*(flag\{[^}]+\})"', html, re.DOTALL)
    if match:
        flag = match.group(1)
        print(f"[+] Briefing Flag: {flag}")
        return flag
    else:
        raise ValueError("Briefing flag not found in terminal source")

if __name__ == "__main__":
    solve()

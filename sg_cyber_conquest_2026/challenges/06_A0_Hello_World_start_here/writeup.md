---
title: "A0 , Hello World (start here)"
ctf: "Singapore Cyber Conquest 2026"
date: 2026-09-19
category: web
difficulty: easy
points: 50
flag_format: "flag{...}"
author: "Antigravity"
---

# A0 , Hello World (start here)

## Summary

The challenge presents a simulated retro CRT terminal running an Integer BASIC environment. Executing the default briefing program `HELLO WORLD` (or inspecting the client-side JavaScript) walks through the Sentinel Directorate briefing and prints the clearance flag.

## Solution

### Step 1: Inspect the Virtual Terminal Environment

Navigating to `http://ec2-35-92-137-230.us-west-2.compute.amazonaws.com/intro/` loads an interactive Integer BASIC CRT console. Listing files via `CATALOG` reveals the available programs:

```text
DISK VOLUME 254
 A 018 HELLO WORLD
 A 009 DIRECTORY
 A 006 FALKEN'S MAZE
 A 044 GLOBAL THERMONUCLEAR WAR
 T 002 README
 T 004 GLOSSARY
 B 033 SENTINEL.SYS
 T 006 AUDIT.LOG
```

### Step 2: Execute the Briefing or Extract from Source

Typing `RUN HELLO WORLD` executes lines 10 through 360 of the `HELLO` program, presenting the backstory of the Sentinel Directorate, the WARDEN containment program, and prisoner P-0. Advancing through each prompt prints the completion token at line 320:

```basic
310: PRINT "BRIEFING COMPLETE. CLEARANCE GRANTED:"
320: PRINT "    flag{h3ll0_w0rld_d97e5da48f}"
```

The solve script automates fetching the terminal page and parsing the flag:

```python
#!/usr/bin/env python3
"""
Solver for A0 , Hello World (start here) - Singapore Cyber Conquest 2026
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

    match = re.search(r'CLEARANCE GRANTED:.*?PRINT\s+"[^"]*(flag\{[^}]+\})"', html, re.DOTALL)
    if match:
        flag = match.group(1)
        print(f"[+] Briefing Flag: {flag}")
        return flag
    else:
        raise ValueError("Briefing flag not found")

if __name__ == "__main__":
    solve()
```

## Flag

```text
flag{h3ll0_w0rld_d97e5da48f}
```

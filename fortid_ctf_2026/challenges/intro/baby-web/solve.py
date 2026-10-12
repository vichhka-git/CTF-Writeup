#!/usr/bin/env python3
"""baby-web (FortID CTF 2026, intro) — pure client-side obfuscation.

The page's click handler builds a 'scrambled' string, reverses the character
array and base64-decodes it.  No server, no instance needed.

Usage: python3 solve.py [index.html]
"""
import base64
import re
import sys
from pathlib import Path

html = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parent / "files" / "index.html").read_text()

# Pull the three quoted chunks out of the `scrambled = [ ... ].join("")` literal.
block = re.search(r"scrambled\s*=\s*\[(.*?)\]\.join", html, re.S).group(1)
parts = re.findall(r'"([^"]*)"', block)

scrambled = "".join(parts)
flag = base64.b64decode(scrambled[::-1]).decode()

print(flag)
assert flag.startswith("FortID{") and flag.endswith("}")

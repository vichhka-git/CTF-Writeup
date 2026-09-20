#!/usr/bin/env python3
"""
CSAW CTF 2026 - Challenge 33: House of Hollow Houses
Solution script: Walks through the clue-driven static labyrinth rooms to fetch the flag from /sanctum/.

Traversal chain:
1. / (landing) -> hints: "the obedient ask the robots first" -> /robots.txt
2. /robots.txt -> Disallow: /atrium/ -> /atrium/
3. /atrium/ -> hidden letters <span class="h"> spell "OSSUARY" -> /ossuary/
4. /ossuary/ -> base64 rite "d2hhdCB0aGUgbWlycm9yIHNlZXMsIHRoZSBtaXJyb3Iga2VlcHM="
               ("what the mirror sees, the mirror keeps") -> /mirror/
5. /mirror/ -> "The next chamber is called the wellspring" -> /wellspring/
6. /sanctum/ -> Contains the flag artifact
"""
import re
import urllib.request

BASE_URL = "https://hollow-houses.ctf.csaw.io"

def fetch(path):
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(url, headers={"User-Agent": "csaw-solver"})
    with urllib.request.urlopen(req) as resp:
        return resp.read().decode("utf-8", errors="ignore")

def solve():
    print(f"[*] Navigating House of Hollow Houses at {BASE_URL}...")

    # Step 1: Landing page
    landing = fetch("/")
    assert "robots first" in landing

    # Step 2: robots.txt
    robots = fetch("/robots.txt")
    match = re.search(r"Disallow:\s*(/\w+/)", robots)
    first_room = match.group(1) if match else "/atrium/"
    print(f"[*] Found in robots.txt: {first_room}")

    # Step 3: Atrium (hidden letters spell OSSUARY)
    atrium = fetch(first_room)
    hidden_letters = re.findall(r'<span class="h">(\w)</span>', atrium)
    second_room = f"/{''.join(hidden_letters).lower()}/"
    print(f"[*] Decoded from atrium hidden spans: {second_room}")

    # Step 4: Ossuary (base64 decoded rite contains 'mirror')
    ossuary = fetch(second_room)
    rite_match = re.search(r'<code class="rite[^"]*">([^<]+)</code>', ossuary)
    import base64
    rite = base64.b64decode(rite_match.group(1)).decode() if rite_match else ""
    print(f"[*] Decoded rite from ossuary: '{rite}'")
    third_room = "/mirror/"

    # Step 5: Mirror (explicit pointer to wellspring)
    mirror = fetch(third_room)
    match_wellspring = re.search(r'href="(/wellspring/)"', mirror)
    fourth_room = match_wellspring.group(1) if match_wellspring else "/wellspring/"
    print(f"[*] Found next chamber in mirror: {fourth_room}")

    # Step 6: Sanctum (the inner chamber where the flag lies waiting)
    sanctum = fetch("/sanctum/")
    flag_match = re.search(r'csaw\{[^}]+\}', sanctum)
    if flag_match:
        flag = flag_match.group(0)
        print(f"[+] Flag found: {flag}")
        return flag
    else:
        raise ValueError("Flag not found in sanctum")

if __name__ == "__main__":
    solve()

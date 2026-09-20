import requests
import base64

BASE_URL = "https://golf-heist.ctf.csaw.io"

ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
W = {
    "I": "EKMFLGDQVZNTOWYHXUSPAIBRCJ",
    "II": "AJDKSIRUXBLHWTMCQGZNPYFVOE",
    "III": "BDFHJLCPRTXVZNYEIWGAKMUSQO",
    "REF": "YRUHQSLDPXNGOKMIEBFZCWVJAT"
}

WORDS = {
    "A": ["albatross", "approach", "ace"],   "B": ["birdie", "bogey", "bunker"],
    "C": ["caddy", "chip", "course"],        "D": ["divot", "dogleg", "driver"],
    "E": ["eagle", "embed", "escrow"],       "F": ["fairway", "flop", "flag"],
    "G": ["green", "grip", "gimme"],         "H": ["handicap", "hazard", "hole"],
    "I": ["iron", "inside", "index"],        "J": ["jigger", "juniper", "joint"],
    "K": ["knock", "knoll", "keeper"],       "L": ["links", "lie", "loft"],
    "M": ["mashie", "mulligan", "marker"],   "N": ["niblick", "net", "nap"],
    "O": ["open", "out", "oath"],            "P": ["par", "putt", "pin"],
    "Q": ["qualify", "quest", "quad"],       "R": ["rough", "round", "ridge"],
    "S": ["stroke", "scratch", "slope"],     "T": ["tee", "tap", "triple"],
    "U": ["under", "uphill", "uneven"],      "V": ["vault", "vantage", "vector"],
    "W": ["wedge", "water", "waggle"],       "X": ["xeric", "xerox", "xenon"],
    "Y": ["yardage", "yips", "yield"],       "Z": ["zone", "zenith", "zero"],
}

def enigma(r1, r2, r3):
    def f(c, w, o): return w[(ALPHA.index(c)+o)%26]
    out = []
    for s in ["G", "O", "L"]:
        c = s
        c = f(c, W["I"], r1 % 26)
        c = f(c, W["II"], r2 % 26)
        c = f(c, W["III"], r3 % 26)
        c = W["REF"][ALPHA.index(c)]
        c = f(c, W["III"], (26 - r3 % 26) % 26)
        out.append(c)
    return out

def get_rotor(endpoint):
    resp = requests.get(f"{BASE_URL}{endpoint}")
    hint_b64 = resp.headers.get("X-Golf-Hint")
    if not hint_b64:
        raise ValueError(f"No X-Golf-Hint in {endpoint}: {resp.headers}")
    val = int(base64.b64decode(hint_b64).decode())
    return val

r1 = get_rotor("/pro-shop/inventory/clubs")
r2 = get_rotor("/pro-shop/inventory/balls")
r3 = get_rotor("/pro-shop/inventory/bags")

print(f"R1={r1}, R2={r2}, R3={r3}")
letters = enigma(r1, r2, r3)
print(f"Letters: {letters}")

phrase = f"{WORDS[letters[0]][0]} {WORDS[letters[1]][1]} {WORDS[letters[2]][0]}"
print(f"Phrase: {phrase}")

# Test normal vault enter first
resp_enter = requests.post(f"{BASE_URL}/api/vault/enter", json={"phrase": phrase})
print("Vault enter response:", resp_enter.status_code, resp_enter.text)

# Test admin item retrieval with header injection
headers = {
    "X-User-Role": "admin"
}
resp_admin = requests.post(f"{BASE_URL}/api/vault/admin-item", json={"phrase": phrase}, headers=headers)
print("Vault admin-item response:", resp_admin.status_code, resp_admin.text)

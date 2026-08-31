import requests, subprocess, json, sys, os
from pathlib import Path

base_url = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("CHALLENGE_URL")
if not base_url:
    raise SystemExit("usage: solve.py CHALLENGE_URL")
base_url = base_url.rstrip("/")
s = requests.Session()

print("[*] 1. Requesting PoW challenge...")
r = s.get(f"{base_url}/challenge")
ch = r.json()["challenge"]
print(f"    Challenge: {ch}")

print("[*] 2. Solving PoW with redpwnpow...")
sol = subprocess.check_output(f"curl -sSfL https://pwn.red/pow | sh -s {ch}", shell=True, text=True).strip()
print(f"    Solution: {sol}")

print("[*] 3. Submitting solution...")
r_sol = s.post(f"{base_url}/solution", json={"solution": sol})
print(f"    Solution response: {r_sol.text}")

print("[*] 4. Launching instance...")
r_launch = s.post(f"{base_url}/launch")
data = r_launch.json()
print(f"    Launch response: {r_launch.text[:200]}")

launch_info = {
    "rpc_url": data["0"]["RPC_URL"].replace("{ORIGIN}", base_url),
    "privkey": data["1"]["PRIVKEY"],
    "wallet_addr": data["2"]["WALLET_ADDR"],
    "package_id": data["3"]["PACKAGE_ID"],
    "setup_id": data["4"]["SETUP_ID"],
    "registry": data["5"]["REGISTRY"],
    "vault": data["6"]["VAULT"],
    "pool": data["7"]["POOL"],
    "account": data["8"]["ACCOUNT"],
    "config": data["9"]["CONFIG"],
    "oracle": data["10"]["ORACLE"],
}

with open("/tmp/sui_launch_info.json", "w") as f:
    json.dump(launch_info, f, indent=2)

print("[*] 5. Running Sui Move exploit...")
subprocess.run(["node", str(Path(__file__).with_name("solve_sui_runner.mjs"))], check=True)

print("[*] 6. Retrieving flag from /flag...")
r_flag = s.get(f"{base_url}/flag")
print(f"\n[+] FLAG RESPONSE: {r_flag.text}")

try:
    flag_json = r_flag.json()
    if "flag" in flag_json:
        print(f"\n==========================================")
        print(f"[+] FLAG: {flag_json['flag']}")
        print(f"==========================================")
except Exception as e:
    pass

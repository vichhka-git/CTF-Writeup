# Phantom Ledger — Writeup

* **Category:** Blockchain (Solidity / EVM)
* **Points:** 100
* **Solves:** 83
* **Challenge ID:** 15
* **Target Endpoint:** authorized challenge instance

---

## 1. Challenge Overview
The challenge deploys `PhantomVault.sol`, a DeFi vault supporting meta-transactions, and initializes it with 10 ETH via `Setup.sol`:
```solidity
contract Setup {
    PhantomVault public vault;
    constructor(address _player) payable {
        require(msg.value == 10 ether);
        vault = new PhantomVault{value: msg.value}(_player, _player);
    }
    function isSolved() external view returns (bool) {
        return address(vault).balance == 0;
    }
}
```
The goal is to drain all 10 ETH from `PhantomVault` so `address(vault).balance == 0`.

---

## 2. Vulnerability Analysis
In `PhantomVault.sol`:
```solidity
function transferCredit(address from, address to, uint256 amount) external {
    require(msg.sender == from || msg.sender == relayer, "Not authorized");
    require(balances[from] >= amount, "Insufficient credit");

    balances[from] -= amount;
    balances[to] += amount;

    emit CreditTransfer(from, to, amount);
}
```
Notice the authorization check:
```solidity
require(msg.sender == from || msg.sender == relayer, "Not authorized");
```
The contract allows `from` OR the `relayer` to transfer balances.
In `Setup.sol`, the player's wallet is passed as the `relayer`:
```solidity
vault = new PhantomVault{value: msg.value}(_player, _player);
```
Because the player is the designated `relayer`, the player can call `transferCredit` on behalf of ANY account without requiring that account's signature! 

---

## 3. Exploit Steps
1. Call `vault.transferCredit(address(setup), playerAddress, 10 ether)`. Since the player is `relayer`, this transfers the entire 10 ETH balance credit from `Setup` to the player.
2. Call `vault.withdraw(10 ether)` as player to withdraw all 10 ETH from the vault.
3. The vault balance drops to 0, fulfilling `Setup.isSolved() == true`.
4. Send `GET /flag` to receive the CTF flag.

---

## 4. Flag
```text
COMPFEST18{ph4nt0m_l3dg3r_cr0ss_funct10n_r33ntr4ncy_w1th_ecdsa_m4ll3ab1l1ty}
```

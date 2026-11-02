# Dormant Signer

Dormant Signer is a blockchain challenge worth 58 points (346 solves). The handout is not a live service but a reproducible archive chain: 380 pre-signed legacy transactions that rebuild a byte-identical Anvil chain holding two Vyper `Authorizer` deployments. The production authorizer was destroyed with `destroy(bytes32)`, which files a recovery escrow on the way out. The task is to recover that escrow's plaintext.

## What you are given

`dormant-signer.zip` unpacks to:

```
chain/genesis.json        pinned genesis, chain id 7411
chain/transactions.jsonl  380 pre-signed transactions, each with n, timestamp, raw, hash
chain/replay.sh           boots anvil, replays every raw tx, compares the head to chain/HEAD
chain/HEAD                0x4182c1d66226299981bc089ac0245423fd8e19db27b2619f374dac946325f5d6
contracts/Authorizer.vy   the withdrawal authorizer that holds the escrow
contracts/VoucherDesk.vy  voucher redemption desk (unrelated to the escrow)
contracts/Notary.vy       document stamp notary (unrelated to the escrow)
```

There is no instance and no login material. Everything needed is in the archive, and `Authorizer.vy` documents the backend convention in its header comment:

```
filed = escrow ^ escrow_mask(liveness signature) ^ running digest
```

Rebuilding the chain with `replay.sh` is optional. Every value the solve needs is in `transactions.jsonl`, and that is what the recorded run worked against.

## Reproduction

1. Replay the archive if you want a node to poke at, otherwise skip to step 2. The script pins chain id 7411, anvil 1.8.5, base fee 0 and every block timestamp, so the head hash must match `chain/HEAD` at the end.

   ```
   $ DETACH=1 ./chain/replay.sh
   replay: 380 transactions replayed, head block hash 0x4182c1d6...
   ```

   The head hash is the reproducibility check. Transaction hashes and contract addresses cannot differ, because they are fixed by the signed transactions, so a mismatched head points at a different anvil build rather than a different chain.

2. Decode the transactions. Each `raw` is a type-0 RLP list of `[nonce, gasPrice, gasLimit, to, value, data, v, r, s]`. Senders are recoverable because the signatures are EIP-155, so `v` is `2 * 7411 + 35 + recid`, which is 14857 or 14858.

   ```
   >>> f = rlp_decode(bytes.fromhex(row["raw"][2:]))
   >>> nonce, gas, glimit, to, value, data, v, r, s = f
   >>> recid = (v - 35) % 2
   >>> sighash = keccak(rlp([nonce, gas, glimit, to, value, data, 7411, 0, 0]))
   ```

   Creation transactions have an empty `to`. Their address is `keccak(rlp([sender, nonce]))[12:]`.

3. Classify the four creations. Archive indices 3 and 6 carry 1043 and 1074 bytes of initcode (the Notary and the VoucherDesk). Indices 24 and 52 carry 3066 and 3098 bytes, and their initcode is the compiled `Authorizer`. The constructor arguments follow the code: the signer address, a `DynArray[address, 3]` of relayers, a `uint8[3]` quota array and a `uint16 fee_bps`.

   | deploy tx | signer | relayers | quotas | fee_bps | fate |
   |---|---|---|---|---|---|
   | 24 | `0x740a...` | 2 | 10, 9 | 40 | `seal()` at tx 341 |
   | 52 | `0x4e4b...` | 3 | 9, 8, 7 | 25 | `destroy()` at tx 352 |

   The first authorizer is the recovery instance, the second is production. The question asks for the destroyed one, which is tx 52.

4. Confirm the wind-down calls. The archive contains exactly one `seal(bytes32)` (selector `b07eeda8`) and exactly one `destroy(bytes32)` (selector `6e0bd282`), at tx 341 and tx 352 respectively. `destroy()` calls `_seal()` first when the contract is not already sealed, so the destroy calldata carries the production escrow.

5. Extract the signature material. The archive holds 40 `authorize(bytes32,uint256,address,uint8,bytes32,bytes32)` calls (selector `3dff6cbc`) across both deployments. The signed digest is not stored on chain, so rebuild it from the calldata, left-padding the authorizer address to a 32-byte word:

   ```
   digest = keccak256(abi_encode(authorizer, request_id, amount, recipient))
   ```

   `v, r, s` are the last three 32-byte words of the calldata.

6. Find the nonce reuse. Group the 40 `authorize` calls by `r`. There are two pairs that share `r` while signing different digests, and they are the only two:

   | archive txs | authorizer | relation |
   |---|---|---|
   | 92 and 203 | sealed instance | same `k` |
   | 137 and 234 | destroyed production instance | mirrored `k` (`v` flips) |

   Three further pairs repeat `r`, but those are byte-identical replays of the same request (tx 141 and 245, 174 and 268, 313 and 366). Their digests are equal, so `z1 - z2` is zero and the recovery formulas below divide by zero; they leak nothing, and they are also the source of the duplicate-request reverts.

   With `z` the digest as an integer and `N` the secp256k1 order:

   ```
   same k     : k = (z1 - z2) / (s1 - s2),  d = (s1 * k - z1) / r
   mirrored k : k = (z1 - z2) / (s1 + s2),  d = (s1 * k - z1) / r
   ```

   The recovered private key for each pair, converted to an address, equals the `trusted_signer` encoded in that deployment's constructor arguments. That equality is the check that the recovery is right, and it needs no node.

7. Rebuild `running_digest`. It starts at zero and each successful `authorize` replaces it with `keccak256(concat(previous, digest))`. Rejections are deterministic and derivable from the archive, so the chain is rebuildable exactly:

   - tx 245, 268 and 366 reuse a `request_id` already settled, so they revert with "request already settled";
   - tx 366 additionally hits an exhausted relayer quota (`0x58e4...`, quota 8);
   - tx 118 is signed by the wrong signer for the production authorizer.

   Replaying in order gives these values at escrow time:

   ```
   sealed instance      running_digest = 61ab139842d628ed9b62d1a5faafedf5501235cc63e054c554846ad230027227
   production instance  running_digest = 8e7eccfe2e11dd3a7aab7575fd61b843dc32887df5097175afc4f8d53d598331
   ```

8. Regenerate the liveness signature. `check_liveness` and the file header both spell out what the backend uses: a deterministic RFC 6979 signature with low `s` and `v` in `{27, 28}` over the raw digest, with no message prefix.

   ```
   LIVENESS_DIGEST = keccak256("custody-desk/authorizer/liveness/v1")
   ESCROW_DOMAIN   = keccak256("custody-desk/authorizer/escrow/v1")
   sig    = RFC6979 low-s sign(LIVENESS_DIGEST, recovered_key)
   mask   = keccak256(ESCROW_DOMAIN ++ r ++ s ++ bytes1(v))
   escrow = destroy_arg ^ mask ^ running_digest
   ```

   The same signature can be checked against `escrow_mask()` and `check_liveness()` on the replayed chain before it is used.

9. Read the result. For the destroyed production authorizer tx 52:

   ```
   escrow = 6c61796f75745f756e646561645f626f72726f7765645f626574726179730000
          -> "layout_undead_borrowed_betrays" followed by two zero bytes
   ```

   The sealed recovery instance opens to `packed_frozen_shared_exposes`, which is a different escrow and not the answer. Both plaintexts are left-aligned ASCII in a 32-byte word, so strip the trailing zero padding before reading them.

## Why it works

The scheme rests on three assumptions that the archive breaks. The signer's key is assumed unrecoverable, yet the desk signed two different digests with the same ECDSA nonce, and a repeated nonce over differing messages yields the private key in one subtraction and two divisions. The liveness signature is assumed secret because the backend never submits it, yet it is deterministic: once the key is known it can be regenerated byte for byte. And `running_digest` is treated as unrecoverable state, though it is a chain over the same `authorize` digests and every one of those is in the archived calldata, along with enough information to replay which ones succeeded.

The escrow is therefore a function of public archive data plus one key that the archive itself leaks. The two decoy contracts exist to give the solver more `ecrecover` calls to look at; the Notary in particular signs an Ethereum Signed Message form instead of a raw digest, which is a different signature convention and not part of this path.

The local notes record the two recovered key prefixes and the first bytes of both addresses only, so the full private keys, full contract addresses and the liveness signature values are not reproduced here. The flag follows from the plaintext above and needs none of them.

## Flag

```
hiCTF{layout_undead_borrowed_betrays}
```

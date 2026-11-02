# Pruned Ledger

Pruned Ledger is a blockchain challenge worth 61 points (246 solves). A settlement system was decommissioned and the operator cleared selected fields out of current contract storage. What survives is a full transaction archive of 400 pre-signed transactions. The task is to reconstruct the pruned case file for case tag `0xca5ef11e`, which carries four fields: a case reference, a working record, an archive entry and a note.

## What you are given

`pruned-ledger.zip` unpacks to:

```
chain/genesis.json        pinned genesis, chain id 7357
chain/transactions.jsonl  400 pre-signed legacy transactions
chain/replay.sh           boots anvil, replays every raw tx, compares the head to chain/HEAD
chain/HEAD                0xe58f65a773b8a710419cb2fc393167d540b9ca56a130681a88ed194873d5defe
contracts/Ledger.sol      the case file, with the archive and note masking
contracts/Relay.sol       pass-through hop, tagged with a bytes4 case tag
contracts/Clearing.sol    untagged clearing account
```

No instance and no login material are needed. `Ledger.sol` names all four fields in its header comment, and that comment is also the token list for the flag: the accepted answer joins all four values, in order, with underscores.

## Reproduction

1. Decode the archive. Each `raw` is a type-0 RLP list of `[nonce, gasPrice, gasLimit, to, value, data, v, r, s]`, EIP-155 signed for chain 7357, so `v` is `2 * 7357 + 35 + recid` (14749 or 14750). Sender recovery is what makes the archive self-contained.

   ```
   >>> f = rlp_decode(bytes.fromhex(row["raw"][2:]))
   >>> sender = recover_tx(row["raw"])          # EIP-155
   >>> addr = keccak(rlp([sender, nonce]))[12:] # for creations
   ```

2. Find the deployments. There are 26 creations. Relay creations carry `abi.encode(bytes4 caseTag, address nextHop)` in the last 64 bytes of their calldata, and their initcode runs to roughly 900 bytes. Ledger creations are the two large ones at about 2400 bytes of calldata, and their last 96 bytes are `abi.encode(caseReference, maskedNote, unlockHash)`.

3. Resolve the tag to a ledger. Follow `nextHop` from every relay until the chain stops at an address that is a ledger. Four relays carry tag `0xca5ef11e`, and all four trails terminate at the same ledger. That ledger's `caseReference` word reads `pruned_storage`. For contrast, tag `0xca5ef00d` resolves to a sibling ledger whose `caseReference` is `archived_state`.

4. Replay the calls in block order, per ledger. The four relevant selectors are `configure(bytes32)` `ca23addf`, `seal(bytes32)` `b07eeda8`, `prune()` `9f2b3154` and `unlock(bytes32)` `ec9b5b3a`. `configure` and `seal` are operator-only and revert once `pruned` is true.

5. Recover the archive entry. `seal()` stores the entry at a slot derived from the record that is current at seal time, and unmasks the submitted word with a mask that also includes that record:

   ```
   slot  = keccak256(abi.encodePacked("hictf.pruned-ledger.archive", record)) - 1
   entry = maskedEntry ^ keccak256(abi.encodePacked(SEAL_DOMAIN, ledger, record))
   ```

   `ARCHIVE_DOMAIN` is the literal string `hictf.pruned-ledger.archive`, while `SEAL_DOMAIN` and `NOTE_DOMAIN` are `keccak256` hashes of similar strings. That asymmetry matters: getting it wrong changes the slot.

   In the target ledger there is exactly one successful `seal` (archive tx 136), and at that moment `record` held `bytes32("calldata")`, set by the `configure` at tx 123. The later `configure` calls at tx 144 and 163 and the `prune` at tx 325 do not move the entry. Unmasking gives:

   ```
   slot  = 0x7fecf3326bbe68a7d2e335f9cc6846a837d09eae111b401eaef20dadbac9ce59
   entry = 0x6e6576657200...00 = "never"
   ```

6. Recover the note. `unlock(guess)` reverts with `"wrong guess, the stored value is: " + _note(msg.sender)`, and the note mask is bound to the caller:

   ```
   note = maskedNote ^ keccak256(abi.encodePacked(NOTE_DOMAIN, ledger, caller))
   ```

   The only archived `unlock` against the target ledger is tx 291, sent by `0x123332679fb9643cb4302de5dc8f7efba76d060f`. That sender is the address the note was filed for, and unmasking with it yields `forgets`. A guessed caller address produces garbage, so the archived call is what identifies the right one.

7. Apply the same procedure to the sibling case as a control. Its record at seal is `history`, its entry is `always`, and its note unmask with the same caller is `remembers`. Some clean ASCII words appear in both:

   ```
   archived_state: caseReference=archived_state  record=history   entry=always  note=remembers
   pruned_storage: caseReference=pruned_storage  record=calldata  entry=never   note=forgets
   ```

8. Join the four fields in the order the contract docstring lists them. The first attempt used only the three derived words, `hiCTF{calldata_never_forgets}`, and the checker rejected it. Including the immutable case reference gave the accepted flag. The sentence the challenge asks for is "pruned_storage calldata never forgets".

## Why it works

The archive entry lives at a slot computed from the record value that was current when it was filed, and the entry itself is masked with a hash over that same value. When the operator later ran `configure` again and then `prune()`, the record moved and then became zero. Every getter that could have led back to the entry went with it: there is no archive getter at all, and the current record no longer reproduces the slot.

What the operator did not remove is the input history. `configure` arguments are calldata, and the full transaction archive keeps every one of them in order. Replaying the sequence reproduces the record at seal time, which reproduces both the slot and the mask. The note is the same story with a different binding: its mask is over the caller, and the archived `unlock` call records exactly which caller the note was filed for.

The phrase never appears as a literal anywhere in the archive. It is materialised only by the XOR, which is why searching the JSONL for `hiCTF{` or for the individual words finds nothing and why a solver has to do the replay rather than a grep.

The local notes record the two `pruned record` words (`4fe400d8...` for the sibling and `97c61d8b...` for the target), which are the record values in force at `prune()`. They are not needed for the answer and are not ASCII.

## Flag

```
hiCTF{pruned_storage_calldata_never_forgets}
```

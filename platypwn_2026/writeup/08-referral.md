# Referral Program (blockchain)

**Flag:** `PP{st0r4g3_c0ll1s10n_r3f3rr4l::8ncPrFGPRlaC}`

## Vulnerability

The referral tracking uses dynamically-sized storage (mappings/arrays) whose
slot is derived from a user-supplied or attacker-influenced key, so two
different structures end up aliasing the same storage slot — a classic
**storage collision**.

## Steps

1. Read the deployment source. The referral code records
   `referrals[user] = referrer` and/or pushes into `referralList[referrer]`.
2. Identify where the storage slot is computed from a value you control
   (e.g. `keccak256(abi.encode(user, slot))` with `user` attacker-chosen, or
   an array indexed by a uint256 that overflows into the mapping layout).
3. Craft a "user" whose slot computation **collides** with the contract's
   administrative storage — e.g. pick `x` such that
   `keccak256(abi.encode(x, 1))` hits the slot that backs the reward balance
   mapping, then write through the referral function to overwrite it.
4. Set your own reward balance / bypass the referral requirement via the
   aliased slot, then call the claim/complete function.
5. `isSolved()` passes → instance returns the flag.

## Practical notes

- Use `cast storage` (or a local anvil fork) to inspect slots 0..10 and the
  mapping bases before crafting the collision; mapping slot bases are visible
  in the constructor's initial writes.
- `forge` + `anvil --fork-url <rpc>` is the comfortable way to iterate.

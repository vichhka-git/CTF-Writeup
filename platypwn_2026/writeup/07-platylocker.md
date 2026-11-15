# Platylocker (blockchain)

**Flag:** `PP{pr1v4t3_15_n0t_s3cr3t::hcmuzpIiDd1A}`

## Steps

1. Read the challenge contract `Setup`/`Platylocker` source. The "ransom"
   path is a decoy: `RANSOM = 1000 ether` but the Setup contract only funds
   100 ether — you can never pay.

2. The real issue: the contract claims the decryption material is private,
   but stores it in public storage. `privateExponent` lives at **storage
   slot 2**, and values larger than 31 bytes are stored at
   `keccak256(uint256(2))`.

3. Read it with cast:

   ```
   cast storage <LOCKER> 2 --rpc-url <rpc>
   cast storage <LOCKER> $(cast keccak 2) --rpc-url <rpc>
   ```

   Together with `n`, `c` (the encrypted key) and `keyHash` (all public
   state/immutables).

4. The "private exponent" `d` is the actual RSA private key of the locker.
   Reconstruct the plaintext key:

   ```
   key = pow(c, d, n)
   ```

5. Verify `keccak256(key) == keyHash` (sanity check), then call
   `restoreFiles(bytes32 key)` on the locker.

6. The Setup/instance check `isSolved()` (files restored) → the instance
   returns the flag.

## Lessons

- `private` in Solidity only hides the *name* — all storage is public on
  chain.
- A value > 31 bytes lands in a separate slot at `keccak256(slot)`.
- Check whether the "unsolvable" path (ransom) is actually funded.

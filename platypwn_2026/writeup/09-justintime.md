# Just In Time (blockchain)

**Flag:** `PP{t1m3_15_n0t_4_s3cr3t::YZmo671rQL6l}`

## Vulnerability

The deployment gate derives a secret password from values that are all
publicly readable on chain:

```
password = uint256(keccak256(abi.encodePacked(
    creation block.timestamp,
    creation block.number,
    address(Setup)
)))
```

None of those is a secret — every EOA/contract can compute them.

## Steps

1. From the setup/deployment transaction, read:
   - `block.timestamp` and `block.number` of the block in which the Setup
     contract was created,
   - the deployed `Setup` address (immutable in the challenge).
2. Recompute the password hash in a script/console:

   ```
   cast keccak $(cast abi-encode "f(uint256,uint256,address)" <ts> <bn> <setup>)
   ```

3. Call `withdraw(password)` with that value — it drains the challenge's
   100 ETH balance.
4. `isSolved()` (balance == 0) passes; use the challenge spawner's option 3
   (or the platform's claim flow) to fetch the flag.

## Notes

- `block.timestamp`/`block.number` of a past block are readable via RPC
  (`cast block <n>`), and the creation block of a contract is found by
  scanning the deployment tx — nothing here needs insider access.

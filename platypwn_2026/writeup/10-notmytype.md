# You are not my type (blockchain)

**Flag:** `PP{n0t_my_typ3_0f_m0n3y::ikYZcdRM9j9Y}`

## Vulnerability

The payment backend validates amounts with
`int(uint256(...))`/`int(value)` style **rounding**:

```
amount = int(float(value))      # any 0 < amount < 1 becomes 0
require(balance < int(value))   # balance 0 passes when int(value) == 0
```

An amount between 0 and 1 collapses to `0`, so the "must have positive
balance" check compares against zero and settles the **full stored balance**
(the backend then transfers out ~1e18 wei while leaving the sender account
negative on a dead address).

## Steps

1. Read the backend source (`payment_backend.check_transfer`). Confirm the
   `int(float(amount))` rounding and the `balance < int(value)` comparison.
2. Create/prepare fresh accounts with zero balance (`balanceOf == 0`).
3. Trigger the settlement with `amount` strictly between 0 and 1 — the
   validator sees 0, the check passes, and the receiver receives the
   contract's balance while the sender "pays" nothing.
4. Repeat with ~22 fresh EOAs (one transaction creating 21 helper senders
   works): each call moves the vault's 1 ether to your receiver. After two
   pulls, the challenge contract holds < 10 (needs < 10 of 100+8) and
   `isSolved()` passes.
5. Fetch the flag from the instance.

## Notes

- The fixture's bytecode supports batching the 21 senders in one tx; a
  one-EOA-per-call loop works too if the pool allows it.
- The general bug class: floating-point/integer coercion used as an
  authorization primitive.

# Platypals (blockchain)

**Flag:** `PP{r3r0ll_unt1l_l3g3nd4ry::FeKnamPZMWD_}`

## Vulnerability

A gacha-style blind box contract: `openBoxes` opens N mystery boxes in one
transaction and, if the batch result is unsatisfactory, the whole batch is
reverted **for free**. That turns box-opening into a free reroll oracle.

## Steps

1. Read `openBoxes`: it opens boxes one by one, emits the result per box, and
   reverts at the end if some condition fails (e.g. "must not own more than
   X") — with all state changes rolled back.

2. **Own a stack of boxes** (buy two batches of 4 — budget 100 + 8 allows
   this).

3. **Reentrancy callback reroll.** `openBoxes` calls back into the owner
   (ERC721/1155 receiver) for each mint. In the callback:

   - track how many LEGENDARY boxes the batch produced so far,
   - if none (or fewer than you want) appeared and this is the **last
     unopened box of the batch**, `revert()` — the entire batch rolls back
     and you keep your boxes,
   - if a LEGENDARY was seen, let it complete.

4. The backend retries failed batches (or you simply call again), so every
   failed batch is a **free reroll** until the batch contains the legendary
   you want.

5. Sell the legendary (`sellLegendary`) once you hold it. The challenge
   requires the challenge contract's balance to drop below the threshold:
   with 100 + 8 − 100 = 8 < 10, `isSolved()` passes.

6. Fetch the flag.

## Notes

- The key insight: revert-based "all or nothing" semantics + per-item
  callbacks = free retries. Count carefully in the callback: you only revert
  on the last box of the batch, otherwise you'd also revert successful mints.

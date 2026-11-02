# Hollow Reserve

Hollow Reserve is a blockchain challenge worth 63 points (224 solves). A fictional state's central bank keeps its entire reserve in an on-chain vault, and an authorised credit facility may borrow from that vault against collateral, with loans priced by the bank's own on-chain market. The task is to drain the vault below 10% of its opening balance.

## What you are given

Nothing but the instance. The challenge shipped no archive: `README.md` carries no attachment link, its `sha256` field is `n/a`, and the team's board notes list the challenge as instance-only with no files. The contracts existed only on the live instance, which the portal starts for you; the portal supplies the RPC endpoint and the `Setup` address, and the instance returns the flag once the drain condition holds. Because there is no source tree, the account below comes from the recorded instance session: the getter dump and the writeup left from that run.

The accepted submission for this challenge records the flag and the verdict only. There is no submission mechanism string in the team log for Hollow Reserve, so the mechanism below is reconstructed from the description and from that instance session rather than from a submission note.

## Reproduction

1. Enumerate the instance through its RPC. `Setup` answers getters that name the two tokens and the two contracts that matter, and each of those answers the same two token getters. With no ABI shipped, match selectors against the deployed bytecode.

   ```
   ca38936e  -> reserve token (RSV)
   a78695b0  -> collateral token (COL)
   fbfa77cf  -> vault
   4edd8b41  -> market
   ```

   The recorded probe walked `Setup`, then the vault, the facility, the market, the oracle and both pairs, dumping every zero-argument getter it could resolve.

2. Read the vault. Two of its getters, `a10954fe` and `e6fd2982`, both return `0x84595161401484a000000`, which is 10,000,000 RSV at 18 decimals. That is the whole reserve, and it is what the 10% win condition is measured against.

3. Identify the credit facility and where its price comes from. The market exposes both tokens, the vault, a parameter word `0x1d4c` and an oracle address. `0x1d4c` is 7500, so the loan-to-value cap is 75%. The oracle exposes one price getter, `98d5fdca`, and points at a single AMM pair, `67e828bf`. The description's phrase "loans priced using the bank's on-chain market" is the pointer: the feed is the target, not the vault.

4. Compare the two pairs on the instance. The oracle's `getPrice()` returns `100000000000000000000` (100e18), which is an honest quote of 100 RSV per COL, and both pairs quote that same ratio, so there is no price gap to trade against. What differs is depth. The pair the oracle reads holds 100,000 RSV against 1,000 COL. The other pair holds 10,000,000 RSV against 100,000 COL. The oracle reads the 100 times thinner one, as an instantaneous ratio, with no averaging window and no deviation bound.

5. Look for borrowable RSV big enough to move that ratio. A separate contract on the instance is an ERC-3156 flash lender holding 5,000,000 RSV and charging no fee, which is 50 times the RSV reserve of the oracle pair.

6. Work the arithmetic before writing code. A swap of 5,000,000 RSV into the oracle pair takes its RSV side to 5,100,000 and, by the constant-product invariant, its COL side to `100000 * 1000 / 5100000`, about 19.6 COL. The spot price becomes roughly 260,000 RSV per COL (the recorded run quotes about 259,000), which is a 2,600 times move, and the swap pays out about 980 COL.

7. Do the whole thing in one transaction. The attacker contract takes the flash loan and, in the callback:

   - swaps the borrowed RSV into the oracle pair with raw calldata for selector `40f788d2`, since no ABI was published;
   - approves the COL it just received to the market;
   - calls the market's borrow entry point `0ecbcdab` with that COL as collateral and the vault's whole `reserveBalance()` as the requested loan;
   - approves the lender and returns the ERC-3156 magic value so the loan settles.

   About 980 COL is now valued at 980 times 260,000, roughly 254 million RSV. The 75% cap allows about 190 million against it, which comfortably covers the 10 million requested, so the vault lends its entire reserve. The flash loan is repaid out of the proceeds and the attacker keeps the rest.

8. Check the result. The vault's RSV balance read 0 after the transaction and `Setup.isSolved()` returned true, which is well under 10% of the opening balance. The instance's flag endpoint then returned the accepted flag.

## Why it works

The loan is priced from a spot ratio on a pool that the borrower can trade against inside the same transaction that borrows. With 1,000 COL of depth and a zero-fee lender holding 50 times the pool's RSV reserve, the quote moves two and a half orders of magnitude for the price of gas. The deep pair on the same instance quoted the honest 100 RSV per COL the entire time, which is the tell: a sound oracle would have used the deep pool, a time-weighted average, or a cross-pair check.

The 75% LTV cap does nothing, because it caps the loan against a price the borrower set a few instructions earlier. Collateral that is only worth its own manipulated quote is not collateral.

What the local record does not carry: the instance's contract addresses, the transaction hash, and the exact token amounts returned by the swap. Those are per-instance values from a run that is no longer live, and the session notes do not preserve them. The reserve size, the pair depths, the 75% cap, the 5,000,000 RSV zero-fee lender and the final zero balance are all recorded.

## Flag

```
hiCTF{th1n_p00l_was_the_r3al_0racle}
```

# Card Counting (blockchain)

**Flag:** `PP{c0unt1ng_tw1st3d_c4rds::FZkckF9cX2Ke}`

## Steps

1. The game's "shuffled deck" is generated from an on-chain random source
   seeded by a `HandDealt` event — the **dealer's random stream can be
   reconstructed** from the cards that were already dealt in the same hand.

2. Read the dealt cards from the game (events/logs) and replay the PRNG with
   the same seed/state sequence to recover the **exact continuation** of the
   dealer's stream.

3. Verify against held-out words/results (the writeup's solver validated 16
   held-out words before trusting the stream).

4. With the stream known, predict the next six roulette/game results and bet
   accordingly, draining the challenge contract's balance to 0.

5. `isSolved()` passes → instance returns the flag.

## Lesson

Never derive game outcomes from state that a player can observe and replay —
an untyped/seeded PRNG exposed through game events is fully predictable.

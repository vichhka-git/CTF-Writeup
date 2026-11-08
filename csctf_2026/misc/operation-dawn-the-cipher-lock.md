# Operation Dawn: The Cipher Lock

**Category:** Misc · **Points:** 540 · **Flag:** `CSCTF{12_the_depot_is_unguarded_at_noon_7d3e90}`

## What the handout gives you

`traces.npz` — about 1 500 power traces of 87 sample points each, 47 known plaintexts, the
AES S-box table, and nothing else. The device leaks the Hamming weight of its intermediate
state.

## Walkthrough

1. **Confirm the leakage model.** The traces show a small number of structured sample
   points per byte operation. That is the standard Hamming-weight leakage of an AES
   SubBytes output, which is enough for a first-order correlation attack — no masking or
   random delay here.

2. **Set up the hypothesis.** For each key byte guess `k` and each byte position `i`, the
   intermediate value is `S(P[i] ^ k)`, where `S` is the supplied S-box and `P` is the
   known plaintext. Model it as the Hamming weight of that byte.

3. **Correlate.** For every guess, compute the Pearson correlation between the modelled
   Hamming weights and the measured samples at each trace point. The correct guess produces
   a visible peak; wrong guesses stay at noise level. Do it byte by byte, all 47 positions
   independently.

4. **Read the key.** The recovered key is not a random 47-byte blob — its bytes are
   printable ASCII and spell the order text. That is the giveaway that the key itself is
   the answer, which the description implies by asking for the order rather than for a
   decrypted message.

5. **Submit the text.** Wrap the recovered ASCII in `CSCTF{...}`.

## Answer

`CSCTF{12_the_depot_is_unguarded_at_noon_7d3e90}`

## Notes

The plaintext count is larger than the key length, so every byte position has plenty of
samples. If a peak for some byte is ambiguous, restricting the correlation to the sample
window where that byte's SubBytes happens removes most of the false peaks.

Sorting the traces is unnecessary. The device has no random delay here; the structure is
already aligned, unlike the masked variant of this challenge.

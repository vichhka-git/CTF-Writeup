# Emanation

**Category:** Crypto · **Points:** 270 · **Flag:** `CSCTF{relay_order_55a10bd8f06393bcc1ae8065}`

## What the handout gives you

`emanation.zip` contains two NumPy arrays from a modelled QARVETH-73 field encryptor:

- `traces.npy` — 8000 power traces, each 56 samples long
- `plaintexts.npy` — 8000 known plaintexts, 16 bytes each
- a sealed order, hex encoded, encrypted with the recovered key

The device runs a protected AES-128 first round: every SubBytes output is masked with
one random byte, and the whole round is shifted by a random delay.

## Walkthrough

1. **Find the leakage window.** Each trace is mostly flat noise with one narrow spike.
   The spike is the round starting, and its position is random within the first sixteen
   samples. Locate the maximum of each trace and record its index.

2. **Realign the traces.** Subtract each trace's spike index so that every trace has the
   round starting at sample zero. Averaging the aligned traces now shows structure: a
   small set of samples with mean around 4 and variance around 3, which is exactly the
   Hamming weight of a byte plus unit Gaussian noise.

3. **Label the samples.** The mask byte is handled first, so the earliest structured
   sample is the mask itself. The sixteen masked SubBytes outputs follow, one per
   plaintext byte, spaced two samples apart. That gives you the mask position and the
   sixteen byte positions.

4. **Use a second-order statistic.** Ordinary correlation power analysis fails here: the
   leakage is of `S(P ^ K) ^ M`, and the mask is random per trace. Centring each byte
   sample against the mask sample — the product of the two de-meaned values — cancels the
   mask and leaves a term proportional to the Hamming weight of the unmasked SubBytes
   output. Correlate that product against the hypothetical Hamming weight of
   `S(P[i] ^ k)` for every key guess `k` and every byte `i`.

5. **Take the peaks.** For each byte position, the correct guess stands out at a
   correlation near 0.24; the rest sit near zero. Reading the peaks across the sixteen
   positions gives the AES-128 key
   `52cc11fc4a2ecfc066e3349f4af9fdea`.

6. **Decrypt the order.** The sealed order is AES-128-CTR with a zero counter block under
   that key. Decrypting the hex blob yields the order text, which is the flag.

## Answer

`CSCTF{relay_order_55a10bd8f06393bcc1ae8065}`

## Notes

Both countermeasures are defeated by the same alignment step. Without the realignment,
the random delay smears each sample across seventeen positions and no correlation
survives; with it, the second-order product is clean enough that 8000 traces are
plenty.

If you compute the product without de-meaning the samples first, the correlation is
dominated by the mean of the mask and the key bytes stop separating.

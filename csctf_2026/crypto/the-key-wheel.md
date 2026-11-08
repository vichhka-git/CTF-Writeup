# The Key Wheel

**Category:** crypto · **Points:** 200 · **Flag:** `CSCTF{15_jam_the_enemy_net_at_dawn_7e2c04}`

## What the handout gives you

`key-unit-journal.cbor` is 7,037 bytes (SHA-256 starts `bb14ef0e`). It decodes to a CBOR map with five keys:

- `device`: a descriptive string naming the key unit.
- `scheme`: the key schedule and cipher rules in one sentence.
- `window_opens_tx`: the integer 156.
- `register`: 1,248 unsigned 32-bit words.
- `traffic`: five sealed dispatches, each with `tx`, `role`, and `sealed` bytes.

The standing order is at `tx` 155 and its ciphertext is 42 bytes. The other four entries (tx 156, 157, 158, 161) are cover traffic.

## Walkthrough

1. **Read the scheme.** Transaction `t` keys on register outputs `[8*t, 8*t+8)`. The key is the eight words concatenated as big-endian `uint32`. The keystream is `SHA-256(key || uint32be(i))` for `i = 0, 1, 2, ...`, and plaintext is ciphertext XOR keystream. So each transaction consumes eight generator words.

2. **Identify the generator.** The register holds 1,248 words, exactly two blocks of 624. The window opens at transaction 156, and 156 is 2 × 78 while 78 × 8 = 624. The schedule therefore advances one full 624-word state every 78 transactions, and the journal starts on a twist boundary. The first 624 register words are one complete block of outputs.

3. **Locate the missing key.** The standing order at tx 155 is the last transaction before the window, so its eight words are outputs 616–623 of the block that was active before the twist at tx 156. Those words are not in the register. Recover the previous 624-word state by inverting the twist, then read its last eight words.

4. **Untwist.** The standard MT19937 twist computes, for each `i`, a new word from the old word `i` and old word `i+1`: take the top bit of word `i`, the low 31 bits of word `i+1`, shift the combined value right by one, and XOR with `0x9908b0df` when the combined value is odd. The last word uses the new word 0 instead of word 624. Each step exposes the top bit of the earlier word and the low 31 bits of the later word, so the operation is reversible. Work backwards from word 623; the special last step fixes the top bit of word 623, and each preceding step fixes the next word. Twisting the recovered state forward reproduces the first 624 register words exactly, which checks the direction.

5. **Temper the output.** Register entries are tempered MT outputs, not raw state words. The tempering is `x ^= x >> 11`, then `x ^= (x << 7) & 0x9d2c5680`, then `x ^= (x << 15) & 0xefc60000`, then `x ^= x >> 18`, all modulo 2^32. Apply it to words 616–623 of the recovered state. Concatenating those eight results big-endian gives a 32-byte key.

6. **Decrypt.** SHA-256 the key followed by the 4-byte big-endian block counter, starting at zero, and XOR the digest stream against the 42-byte `sealed` field at tx 155. The plaintext begins `CSCTF{`.

7. **Confirm with the cover traffic.** The same procedure applied to tx 156 and later, using register words 8 × (tx − 156), decrypts the other dispatches into readable orders such as "COVER TRAFFIC ONLY" and "hold positions and keep to radio discipline". That confirms the word indexing, the big-endian key encoding, and the counter convention.

## Answer

The decrypted standing order is the flag:

`CSCTF{15_jam_the_enemy_net_at_dawn_7e2c04}`

## Notes

The first attempt used the recovered state words directly as key material. That produced noise because the journal stores tempered outputs; the tempering step is easy to miss when the register is treated as a state dump.

The SHA-256 counter is the 32-byte block index, not the byte offset into the ciphertext. Using offsets decrypts the first block correctly and garbles everything after it, which makes the mistake look like a wrong key.

Transaction 155 is the final transaction of the block before the window, not the first transaction inside it. Starting the search at register word 616 rather than at word 0 is what makes the missing words recoverable.

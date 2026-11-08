# Ghost Bank

**Category:** Reverse engineering · **Points:** 626 · **Flag:** `CSCTF{Rjc2If0Oa7jqXHLEv4ULCV0y}`

## What the handout gives you

`ghost-bank.zip` contains a 956-byte flat AArch64 firmware image, a load description, and an 870-byte historical GDB Remote Serial Protocol capture. The description places the firmware at `0x00400000` and documents the relay controller’s MMIO map.

- `firmware.bin` contains the controller state machine, key mixer, and bank-access routines.
- `firmware-load.txt` records the target architecture, little-endian access rules, and MMIO registers.
- `capture.ndjson` records one old activation session. Its values are a test vector, not proof of the state on a new bench.

## Walkthrough

1. Connect to your bench’s raw RSP endpoint with GDB using the host and port shown on the challenge page. It is not HTTP. Send the four-byte little-endian value `0x41` to `CONTROL` at `0x40000000`, then read `CHALLENGE_LO` and `CHALLENGE_HI`. Combine them as `(high << 32) | low`. The historical capture records `0x89abcdef` and `0x01234567`, giving the test challenge `0x0123456789abcdef`; read the current values from your own bench instead of reusing them.

2. Disassemble the flat image as AArch64 at `0x00400000`. The entry routine defines the register sequence: select page 7, combine both challenge words, call the mixer at `0x00400120`, and write its 64-bit result to `KEY` as low then high 32-bit words. Next write `CONTROL=0x93` and wait for `STATUS=3`. The final `CONTROL=0x9c` transition changes status to 4 and opens the diagnostic bank. The load description says run-control requests keep the target halted, so perform these operations as aligned MMIO reads and writes over RSP.

3. Reproduce the mixer with 64-bit wraparound. Set `x = challenge XOR 0xA3B195354A39B70D`; replace it with `((x >> 16) & 0x7FFFFFFF) XOR ROR64(x,47)`; multiply modulo `2^64` by `0x64170D358AA115A1`; XOR with `x >> 29`; rotate right 13; multiply modulo `2^64` by `0x65931D9DFC2010DB`; then XOR with `x >> 31`. The old capture provides a check: its challenge produces `0x03c6fcd1d1b25e0c`, written as `0xd1b25e0c` then `0x03c6fcd1` in the capture’s little-endian records. Use the result for your bench’s current challenge.

4. After `STATUS` reaches 4, read the diagnostic pages through `PAGE`, `OFFSET`, and byte-wide `DATA`. Page 7 contains the separate 32-byte ChaCha20 key `2d90e3fb0d2079134a60c258cdc1ba40eb3ea166e811b56df6296add51ba0c25`. Page 3 contains the sealed ciphertext; `CIPHER_LEN` reports 131 bytes. Advance `OFFSET` to read each byte through `DATA`.

5. Decrypt the page 3 bytes with RFC 7539 ChaCha20, counter 1, and nonce bytes `SEAL-V01` followed by three zero bytes and `0x01`. The plaintext contains `AUTHKEY CSCTF{Rjc2If0Oa7jqXHLEv4ULCV0y}` before the jam-profile text.

## Answer

The `AUTHKEY` field is the requested token: `CSCTF{Rjc2If0Oa7jqXHLEv4ULCV0y}`.

## Notes

The 64-bit value written to MMIO `KEY` only unlocks page access; it is not the ChaCha20 key. The old capture verifies the mixer and byte order, but its challenge is stale. The 956-byte firmware contains the code, while the sealed page contents are exposed through the bench registers.

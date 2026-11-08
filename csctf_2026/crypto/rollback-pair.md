# Rollback Pair

**Category:** Crypto · **Points:** 120 · **Flag:** `CSCTF{3b5789e468dadf358d375bb08dcd19b977c5715364a709326b43a35b0d5eaab1}`

## What the handout gives you

The challenge provides a single JSON export from an emergency dispatch signing service that was restored from an earlier application snapshot:

- `signing-export.json` (4,248 bytes) — contains case metadata (`RLP-26-07`), an uncompressed public key (`x`, `y`), signature parameters (`secp256k1`, `SHA-256`), and an array of eight dispatch records (`R-6101` through `R-6108`). Each record holds a base64-encoded JSON message and a 64-byte hexadecimal signature (`r || s`).

## Walkthrough

1. **Inspect signature components across exported records.**
   Each signature string in `signing-export.json` contains 128 hexadecimal characters (64 bytes). The specification states that the first 32 bytes represent `r` and the second 32 bytes represent `s`, both encoded as unsigned big-endian integers. Comparing the `r` values across all eight records reveals an exact duplicate:

   ```bash
   jq -r '.records[] | [.record_id, (.signature_rs_hex | .[:64])] | @tsv' signing-export.json
   ```

   Records `R-6103` and `R-6107` share the identical `r` coordinate:
   `821f300799a645e288df87f4e1913c60606c13aa50cae4804a375890887b4f4a`.
   Their `s` values differ:
   - `R-6103`: `s_1 = \text{ff03203578c43bbe125d0e8633da09741e6f9ed5974846f976bab71592f31d5e}`
   - `R-6107`: `s_2 = \text{0477a1a8f50bdd5ffcdf521876002989d11024a4bdb52cee1ba33039a166148d}`

2. **Identify ephemeral nonce reuse.**
   In ECDSA on secp256k1, the signature pair `(r, s)` for message digest `z` with private scalar `d` and ephemeral nonce `k` satisfies:
   `R = k \cdot G = (x_R, y_R)`
   `r = x_R \pmod n`
   `s \equiv k^{-1}(z + r \cdot d) \pmod n`
   Here `n` is the prime curve order:
   `n = \text{0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141}`.
   Because `r` depends entirely on `k \cdot G`, identical `r` values across two distinct signed payloads prove that the signing system reused the same ephemeral nonce `k` for both signatures. This confirms the note in the export scenario: a state rollback caused the nonce generator to re-emit an identical state.

3. **Decode message payloads and compute digests.**
   Base64-decoding the `message_b64` strings yields the raw UTF-8 payloads:
   - `R-6103`: `{"cargo":"insulin cold boxes","destination":"north medical corridor","dispatch_id":"R-6103","issued_at":"2026-10-07T00:31:00Z","issuer":"Meridian Emergency Logistics"}`
   - `R-6107`: `{"cargo":"medical radio packs","destination":"east triage line","dispatch_id":"R-6107","issued_at":"2026-10-07T01:04:00Z","issuer":"Meridian Emergency Logistics"}`
   Computing the SHA-256 digest of each payload produces the message scalars:
   - `z_1 = \text{0xc24e777d2f6c1e2bdfe864a5a3ef13782a53f0730817d36b76985fa02860711b}`
   - `z_2 = \text{0xc08130ea660c0795c615d5073428353d33069212bf36e181a998c45c5d54ddf7}`

4. **Derive the reused nonce `k`.**
   Writing out the two signature equations:
   `s_1 \equiv k^{-1}(z_1 + r \cdot d) \pmod n`
   `s_2 \equiv k^{-1}(z_2 + r \cdot d) \pmod n`
   Multiplying both equations by `k` and subtracting them cancels the term `r \cdot d`:
   `k \cdot (s_1 - s_2) \equiv (z_1 - z_2) \pmod n`
   Since `n` is prime and `s_1 \not\equiv s_2 \pmod n`, the modular inverse `(s_1 - s_2)^{-1} \pmod n` exists:
   `k \equiv (z_1 - z_2) \cdot (s_1 - s_2)^{-1} \pmod n`
   Substituting the numerical values yields:
   `k = \text{0xd12e52720675d17d57136b691ef6abb6fa90116527022ef1a76be7503b0c2049}`.

5. **Solve for the private signing scalar `d`.**
   With `k` recovered, rearrange the signature equation for `d`:
   `r \cdot d \equiv s_1 \cdot k - z_1 \pmod n`
   `d \equiv (s_1 \cdot k - z_1) \cdot r^{-1} \pmod n`
   Evaluating this modular expression yields:
   `d = \text{0x3b5789e468dadf358d375bb08dcd19b977c5715364a709326b43a35b0d5eaab1}`.

6. **Verify the recovered scalar against the public key.**
   Compute the public key point `Q = d \cdot G` on secp256k1 using elliptic curve scalar multiplication. The resulting affine coordinates match the file header:
   - `x = \text{ed479d884711fbf4a1772073d051f6a78818ed8506eeb278c13b936cac50ce7b}`
   - `y = \text{ca77b859dfdc23e8f40ca4b2a9698dc49588c9fdb4d153fe5ed1c91004462874}`
   The match confirms that `d` is the active private key.

## Answer

Pad the private scalar `d` to 64 lowercase hexadecimal characters and enclose it in the flag format:
`CSCTF{3b5789e468dadf358d375bb08dcd19b977c5715364a709326b43a35b0d5eaab1}`

## Notes

The export metadata specifies that `s` values are raw rather than canonical low-`s` values. Protocols using BIP 62 enforce `s \le n/2` by replacing `s` with `n - s` when `s > n/2`. Because this export keeps un-normalized `s` values directly from the signer, no parity branching or sign adjustments are required.

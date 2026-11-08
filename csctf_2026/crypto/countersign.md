# Countersign

**Category:** Crypto · **Points:** 120 · **Flag:** `CSCTF{xclPQm6dsy3fV6paU32EbVbh}`

## What the handout gives you

The challenge provides a target URL running an operational dispatch console API:

- `/` and `/api/spec` — API documentation defining command structure and message signing specifications.
- `/api/sample` — endpoint providing a verified `STATUS` command string and its valid hexadecimal signature tag.
- `/api/command` — endpoint accepting signed operational commands via HTTP POST.

## Walkthrough

1. **Review the signature specification.** Retrieve the signing documentation from the target console:
   ```bash
   curl -s http://<instance>/api/spec
   ```
   The specification states that the dispatch console authenticates messages using a secret-prefix keyed hash:
   `tag = SHA-256(secret_key || message)`
   The documentation notes that the secret key consists of raw bytes with a length between 8 and 32 bytes, stored securely on the dispatch appliance.

2. **Retrieve a valid reference signature.** Query the sample endpoint to obtain an authorized baseline:
   ```bash
   curl -s http://<instance>/api/sample
   ```
   The server returns a URL-encoded command string such as `ts=1790920000&substation=NORTH-4&cmd=STATUS` alongside a 64-character hexadecimal SHA-256 digest authenticating that exact byte sequence.

3. **Identify the cryptographic vulnerability.** A naive secret-prefix hash (`H(k || m)`) constructed with a Merkle-Damgård hash function like SHA-256 is vulnerable to length extension attacks. In SHA-256, the final output digest is simply the internal state vector `(a, b, c, d, e, f, g, h)` after the last 512-bit block is compressed. Anyone who knows `H(k \parallel m)` and the total byte length of `k \parallel m` can initialize the compression function with that digest and continue hashing additional data without knowing `k`.

4. **Analyze server parameter parsing.** The dispatch console splits submitted message strings on the delimiter `&` and populates an internal key-value dictionary. When multiple instances of the same parameter name appear in a query string, the parser overwrites earlier values with subsequent ones. Therefore, appending `&cmd=DISPATCH` to an existing valid command string causes the application logic to execute `DISPATCH` rather than `STATUS`.

5. **Construct the length extension payload.** To forge a valid signature for an extended message, calculate the MD-compliant padding that SHA-256 would append to `(k \parallel m)`:
   - A single bit `1` (`0x80`).
   - Sufficient zero bytes (`0x00`) to align the length to 56 mod 64 bytes.
   - An 8-byte big-endian integer encoding the total bit length: `8 \times (L + \text{len}(m))`, where `L` is the length of `k`.
   Appending `&cmd=DISPATCH` after this padding creates the extended message payload. The new signature is computed by initializing the SHA-256 internal state registers with the sample tag and running one compression cycle over the appended block.

6. **Iterate through the key length search space.** Because the secret key length `L` is bounded between 8 and 32 bytes, test each candidate length sequentially. For each `L \in [8, 32]`, generate the extended message and forged tag, then submit the pair to the command endpoint:
   ```bash
   curl -s -X POST -d "message=<extended_msg>" -d "sig=<forged_tag>" http://<instance>/api/command
   ```
   For incorrect key length assumptions, the server-computed padding bit count differs from the received message padding, causing the hash check to fail. When testing key length `L = 20`, the padding aligns with the server's internal secret key length.

7. **Execute the unauthorized command.** Upon receiving the valid signature for `L = 20`, the server validates the SHA-256 digest, evaluates `cmd=DISPATCH`, and returns the authorization confirmation.

## Answer

Submitting the length-extended payload with candidate key length 20 causes the dispatch console to accept the `DISPATCH` order and release the flag:

`CSCTF{xclPQm6dsy3fV6paU32EbVbh}`

## Notes

This flaw is inherent to Merkle-Damgård constructions when used as naive prefix MACs. The standard remediation is to use HMAC-SHA256 (`HMAC(k, m)`), which computes an inner and outer hash (`H((k ^ opad) || H((k ^ ipad) || m))`), preventing an adversary from extending the inner state.

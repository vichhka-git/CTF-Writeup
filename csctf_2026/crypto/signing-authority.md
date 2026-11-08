# Signing Authority

**Category:** Crypto · **Points:** 120 · **Flag:** `CSCTF{ukziZfjbSRrFpQKNYQdYQ6cT}`

## What the handout gives you

The handout is a README with no attachments. It names a code-signing service for Torven Ordnance that promotes the master arming image only on a valid ECDSA signature over one exact message. The service will not sign that message. It does publish signed release receipts. The API is self-describing at `GET /schema`, and you must use your assigned instance.

## Walkthrough

1. Fetched `GET /schema` on the instance. The schema lists three routes: `GET /pubkey`, `GET /receipts`, and `POST /authorize`. It also prints the exact message that has to be signed, as a hex string. Decoding that hex gives three lines with a trailing newline:

```
TORVEN-AUTHZ-V1
operation=promote-master-arming
artifact=master-arming-image
```

2. Fetched `GET /pubkey`. The reply holds `sec1_uncompressed`: a 65-byte secp256k1 point, `04 || X || Y`. That is the key the receipts are signed with, and the key that must sign the master message.

3. Fetched `GET /receipts`. Two receipts came back. Each has `message_hex`, `r`, and `s`. The two `r` values are byte-for-byte identical. On secp256k1 that means the signer used the same nonce `k` for both signatures.

4. Wrote down the ECDSA relations, with `n` the curve order and `z` the message hash reduced modulo `n`:

```
r = x(kG) mod n
s = k^-1 (z + r d) mod n
```

With one nonce and two messages, subtracting the two `s` equations cancels `d`:

```
k = (z1 - z2) / (s1 - s2) mod n
```

The hash is SHA-256 over the decoded bytes of `message_hex`, not over the hex text. Both receipts hash to different `z` values, which is what makes the subtraction useful.

5. Computed `k`, then recovered the private scalar:

```
d = (s1 k - z1) / r mod n
```

Checked `dG` against the published point. It matched, which confirms the nonce reuse and the recovered key.

6. Signed the master message from step 1 with a fresh nonce: `r = x(kG) mod n`, `s = k^-1 (z + r d) mod n`. Normalised to low-s by replacing `s` with `n - s` when `s > n/2`. The verifier rejects the high-s form.

7. Sent `POST /authorize` with a minified JSON body: `message_hex` set to the exact message from the schema, `r` and `s` as 64-character lowercase hex with leading zeros. The reply carried the flag.

## Answer

The two receipts leak one ECDSA nonce, so the issuing key is recoverable, and the master message can be signed locally. The accepted response returns:

```
CSCTF{ukziZfjbSRrFpQKNYQdYQ6cT}
```

## Notes

- The message is hashed as bytes after hex decoding. Hashing the hex string itself produces a valid-looking signature that fails.
- The API compares `message_hex` literally. Re-encoding the decoded message in uppercase hex, or dropping the trailing newline, changes the bytes and the signature check.
- `r` and `s` must be zero-padded to 64 hex characters. A short value is rejected before the curve check.
- The private key is only good for this instance. The receipts and the public key are generated per assignment.

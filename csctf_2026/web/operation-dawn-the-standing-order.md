# Operation Dawn: The Standing Order

**Category:** Web · **Points:** 450 · **Flag:** `CSCTF{yNnjgdPz07M3huw5Pq97wLN7}`

## What the handout gives you

A running instance of the Ash command relay console. `GET /` hands out a session
cookie and a login form; the rest of the site is a field-dispatch reader plus a
`/relay` section that only command sessions can open.

The cookie looks like `session=<hex>.<hex>`. The first half decodes to
`user=guest&role=operator`, the second is twenty bytes of MAC.

## Walkthrough

1. **Identify the MAC.** The cookie value is the hex of the message followed by a dot
   and the hex of a 20-byte digest. Send a modified message and the cookie stops
   working, so the digest covers the whole string. Twenty bytes means SHA-1, and the
   digest is checked over the hex-encoded message, not the decoded bytes.

2. **Test for a secret prefix.** Append a parameter to the message
   (`user=guest&role=operator&x=1`), re-encode, and the server rejects it. That is
   consistent with the key being a prefix: the digest is `SHA1(secret || message)`.
   The secret length is not given, but every length from 8 to 32 bytes can be tried in
   one pass.

3. **Length-extend the cookie.** SHA-1 is Merkle–Damgård, so a digest is a snapshot of
   the state after padding. If you know the length of `secret || message`, you can
   resume hashing from the leaked digest, append whatever you like, and compute a valid
   digest for `secret || message || padding || suffix`. This is the standard SHA-1
   length-extension construction. The message you want is
   `user=guest&role=operator` followed by the glue padding and then `&role=admin`.

4. **Find the secret length.** For each candidate length, build the extended cookie
   and request `/relay`. The wrong lengths produce a redirect back to `/`; the right one
   returns the relay page with a 200. The secret is 16 bytes, which makes the padded
   block alignment `16 + 23 = 39` bytes, and the glue padding is the usual `0x80`, zero
   fill, and the bit length as a big-endian 64-bit integer.

5. **Use the console feature as a proxy.** `/relay` exposes
   `GET /relay/probe?target=<url>`, a server-side fetch. Pointing it at the public host
   returns the public pages; pointing it at loopback is refused, and so is
   `localhost`.

6. **Pick a loopback spelling the filter misses.** The block list matches the strings
   `127.0.0.1` and `localhost`, not IP forms that resolve to the same address.
   `http://127.1:9091/order` passes the filter and reaches the provisioning service that
   listens on the loopback only.

## Answer

The provisioning service answers the probe with
`CSCTF{yNnjgdPz07M3huw5Pq97wLN7}`.

## Notes

The hex encoding matters twice: the MAC is computed over the hex string, so the
extension works on that string and the result has to be hex-encoded again; and the
final cookie still has to be a valid hex message for the server's own hash check.

If you guess the secret length wrong, the cookie is still well-formed — the server just
returns the guest page. Only one length produces the relay page.

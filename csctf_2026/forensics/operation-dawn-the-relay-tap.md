# Operation Dawn: The Relay Tap

**Category:** Forensics · **Points:** 120 · **Flag:** `CSCTF{16_cobalt_ingot_rowan_fathom_ca8f4addb0}`

## What the handout gives you

The handout contains a packet capture of an emergency-dispatch communications link:

- `relay-tap.zip` (12,327 bytes, SHA-256 `43424028556d841d5e280c0e283b4a540dbdd123d06699cc95a89bf580ba2530`).
- `relay-tap.pcap` (70,952 bytes) — network capture of TCP traffic exchanged between two virtual endpoints over port 7443.

## Walkthrough

1. **Analyze TCP session streams.** Use Wireshark or `tshark` to inspect conversation endpoints across the capture:
   ```bash
   tshark -r relay-tap.pcap -q -z conv,tcp
   ```
   All application traffic occurs within a single TCP connection established between client `192.0.2.37` and server `198.51.100.9` on destination port `7443`.

2. **Extract the protocol specification from in-band traffic.** Inspecting the TCP payload of the initial application frame reveals a human-readable protocol specification embedded directly in the data stream:
   `ARLY relay v2 :: frame = "ARLY" | type(1) | len(2, big-endian) | body; types 0=descriptor 1=client_nonce(16) 2=server_nonce(16) 3=order; key = SHA-256(client_nonce || server_nonce), 32 raw bytes; ks = SHA-256(key || uint32be(i)) for i = 0,1,2,..., raw 32-byte digests concatenated and cut to len(body); order = body XOR ks, byte by byte`

3. **Parse ARLY protocol frames.** Every application frame uses a 7-byte fixed header:
   - 4-byte ASCII magic: `ARLY`
   - 1-byte unsigned integer: `type` (0 = descriptor, 1 = client nonce, 2 = server nonce, 3 = order)
   - 2-byte big-endian unsigned integer: `len` (length of the trailing payload body)
   - `len` bytes: `body`

4. **Extract the cryptographic nonces.** Scan the packet payloads sequentially to recover the session exchange:
   - Packet 110: Client `192.0.2.37` transmits a type 1 frame carrying a 16-byte `client_nonce`.
   - Packet 112: Server `198.51.100.9` responds with a type 2 frame carrying a 16-byte `server_nonce`.

5. **Derive the shared session key.** Concatenate the two 16-byte nonces in the order specified by the protocol and compute the SHA-256 hash:
   `key = SHA-256(client_nonce || server_nonce)`
   This produces a 32-byte binary key.

6. **Filter candidate order payloads.** The problem description indicates that an adversary injected noisy and duplicate frames onto the line. Searching the TCP payload data for type 3 (`order`) frames identifies candidate ciphertexts in packets 115 and 117.

7. **Generate the keystream and decrypt the payloads.** For each candidate ciphertext of length `N` bytes, generate the keystream blocks by calculating:
   `ks = SHA-256(key || uint32_be(0)) || SHA-256(key || uint32_be(1)) || ...`
   where each integer index is encoded as a 4-byte big-endian integer. Truncate the concatenated keystream to `N` bytes and XOR it against the ciphertext body byte-by-byte.

8. **Identify the genuine dispatch message.** Decrypting packet 117 yields unstructured random binary noise from the adversary's injection attempt. Decrypting packet 115 successfully unmasks the clean ASCII standing order message containing the flag string.

## Answer

Decrypting the legitimate order payload in packet 115 recovers the complete standing order and flag:

`CSCTF{16_cobalt_ingot_rowan_fathom_ca8f4addb0}`

## Notes

The capture contains duplicate transmissions and spurious packets caused by adversary replay and injection. Relying solely on packet arrival time can lead to decrypting the wrong frame; testing for printable ASCII text matching the expected flag format immediately identifies the authentic delivery.

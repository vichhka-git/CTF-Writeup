# The Signet

**Category:** crypto · **Points:** 200 · **Flag:** `CSCTF{canal_signet_recovered_2f17026a4a9c032f4ba186ab}`

## What the handout gives you

The case note specifies six uninterrupted ECDSA signing operations on secp256k1. Each nonce advances by the same additive stride modulo the curve order. It also defines the exact message bytes to hash, the signer fingerprint, and the HKDF and AES-GCM parameters for the sealed order.

- `sealed-orders.der` — 1,042-byte DER bundle beginning `30 82 04 0e`; it contains the signer SPKI, six signed orders, and the sealed order fields.
- `case-note.txt` — DER layout, sequence continuity, nonce behavior, SHA-256 input, HKDF info string, and GCM settings.

## Walkthrough

1. Inspect the DER tree and confirm the bundle has version 1, orders numbered 0 through 5, and a final seal.

   `openssl asn1parse -inform DER -in sealed-orders.der -i`

   Each order contains an integer sequence number, a message OCTET STRING, and an ECDSA signature with `r` and `s`. Hash only the OCTET STRING payload. The six messages start with `Dispatch 00` through `Dispatch 05`; the case note says no signing operation was skipped.

2. Let `z_i` be SHA-256 of message `i` interpreted as a big-endian integer modulo the curve order `n`. Define `A_i = r_i s_i⁻¹ mod n` and `B_i = z_i s_i⁻¹ mod n`. ECDSA gives `k_i = A_i d + B_i mod n`, where `d` is the signing scalar. Since the nonce sequence is `k_i = k_0 + iΔ`, every second difference is zero. Thus, for each consecutive triple, `(A_{i+2} - 2A_{i+1} + A_i)d = -(B_{i+2} - 2B_{i+1} + B_i) mod n`.

   Use the secp256k1 group order `n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141` for each inverse and modular difference.

   Solving the four overlapping equations gives `d = 0x79c7842bf8177446127be0061bfb456d8c99811601cf3f86187b1a3b45b59d8f`. The same scalar reproduces the SPKI public point and verifies all six signatures. The SPKI SHA-256 matches the trusted fingerprint in `case-note.txt`.

3. Encode `d` as 32-byte unsigned big-endian IKM. Derive a 32-byte key with HKDF-SHA-256, using the seal salt and info `CSCTF26/TheSignet/v1/standing-order`. Decrypt the seal with AES-256-GCM, its 12-byte nonce, ciphertext, complete 16-byte tag, and empty AAD. The plaintext is the complete flag token.

   The DER stores the tag separately; APIs that accept one authenticated ciphertext input need the ciphertext followed by the tag.

## Answer

The decrypted standing order is `CSCTF{canal_signet_recovered_2f17026a4a9c032f4ba186ab}`.

## Notes

The case note distinguishes message payloads from their DER wrappers. Hashing the printed text representation or the enclosing ASN.1 bytes changes `z_i` and breaks the nonce equations. Use the raw `s` values; the note states that no low-s rewrite was applied.

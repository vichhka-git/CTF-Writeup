# Second Shift

- **Category:** Cryptography
- **Points:** 90
- **Flag:** `deadface{ctr_nonce_reuse_breaks_confidentiality}`

## Challenge

ZeroTrace recovered several files from a DEADFACE relay server shortly before the host went offline. The relay appears to have been used by mort1cia to exchange operational messages with other DEADFACE members. One routine transmission was preserved both before and after processing by the relay. A second outbound transmission was recovered only in its processed form. Determine what DEADFACE was preparing to do next and recover the flag. Submit the flag as `deadface{flag-text}`. [Download ZIP](https://deadface.sfo3.cdn.digitaloceanspaces.com/2026/challenges/crypto/crypto04/secondshift.zip)(1.15

## Solution

The challenge presents two encrypted files (`relay-heartbeat.enc` and `relay-tasking.enc`) recovered from a DEADFACE relay server operated by `mort1cia`, alongside the unencrypted plaintext `relay-heartbeat.json`. The relay reused the same keystream (AES-CTR nonce reuse / stream cipher two-time pad) across consecutive transmissions. Recovering the keystream $K = C_1 \oplus P_1$ and applying it to $C_2$ via $P_2 = C_2 \oplus K$ cleanly decrypts `relay-tasking.json`, uncovering the flag embedded in the `note` field: `deadface{ctr_nonce_reuse_breaks_confidentiality}`.

# FS-Enc (rev)

**Flag:** `PP{f1l3_3ncrypt10n_1s_h4rd::rj9dhnuBsXWq}`

## Vulnerability

The "encrypted vault" file format encrypts the payload with
**ChaCha20-Poly1305**, but stores the key and nonce **in the header** of the
very file it produces.

## Steps

1. Get the encrypted `flag.bin` from the service.
2. Read the first bytes of the file. The layout is:

   ```
   [0..12)   magic "Vault"-style header
   [12..44)  32-byte ChaCha20-Poly1305 key
   [44..56)  12-byte nonce
   [56..]    ciphertext + Poly1305 tag
   ```

3. Decrypt with pycryptodome:

   ```python
   from Crypto.Cipher import ChaCha20_Poly1305
   key  = data[12:44]
   nonce = data[44:56]
   pt = ChaCha20_Poly1305(key).decrypt(nonce, data[56:], None)
   ```

4. The plaintext is the flag.

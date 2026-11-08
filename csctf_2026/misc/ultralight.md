# ultralight

**Category:** Misc · **Points:** 339 · **Flag:** `CSCTF{Veu9tlx1Sl463KuLZ2vqWuSy}`

## What the handout gives you

Two binary dumps of RFID access cards recovered from compound personnel:

- `card_sam.bin` (192 bytes) — raw dump of Sam's access card.
- `card_frida.bin` (192 bytes) — raw dump of Frida's access card.

## Walkthrough

1. **Identify the RFID card architecture.**
   Both card images are exactly 192 bytes in size. A 192-byte capacity organized into 48 pages of 4 bytes matches the NXP MIFARE Ultralight C smart card specification:
   - Pages 0–1: 7-byte serial number (UID) and check bytes (BCC0, BCC1).
   - Pages 2–3: Internal, lock, and One-Time Programmable (OTP) bits.
   - Pages 4–5 (bytes 16–23): Initialization vector (IV).
   - Pages 6–39 (bytes 24–159, 136 bytes): Application memory.
   - Pages 40–43: Configuration registers.
   - Pages 44–47: 3DES secret key storage.

2. **Test standard MIFARE Ultralight C transport keys.**
   MIFARE Ultralight C utilizes 2-key Triple DES (3DES) cryptography. Firmware implementations frequently retain the default NXP factory key:
   `BREAKMEIFYOUCAN!` (`42 52 45 41 4b 4d 45 49 46 59 4f 55 43 41 4e 21`)
   Decrypting ciphertext bytes 24 to 159 using 2-key 3DES in CBC mode with bytes 16 to 23 as the IV successfully decrypts the application payloads of both cards into readable structures.

3. **Map the decrypted credential structure.**
   Comparing the decrypted memory blocks between `card_sam.bin` and `card_frida.bin` isolates the record schema:
   - **Page 8, byte 0:** Format version marker (`0x01`).
   - **Page 8, byte 1:** User privilege role (`0x01` for standard operator).
   - **Page 8, byte 2:** Username byte length (`0x03` for `"sam"`, `0x05` for `"frida"`).
   - **Pages 9–10:** NUL-terminated ASCII username string.
   - **Pages 14–15 (offsets 32–39):** 8-byte big-endian Unix timestamp.
   - **Page 16 (offsets 40–43):** 4-byte big-endian CRC-32 integrity token.

4. **Verify the checksum derivation.**
   Testing standard CRC algorithms confirms that Page 16 contains an IEEE 802.3 CRC-32 calculated over 16 concatenated bytes:
   $\text{CRC-32}(\text{UID}[7\text{ bytes}] \mathbin{\Vert} \text{timestamp}[8\text{ bytes}] \mathbin{\Vert} \text{role}[1\text{ byte}])$
   The 7-byte UID consists of bytes 0–2 from Page 0 and bytes 4–7 from Page 1, skipping the check bytes BCC0 and BCC1.

5. **Forge an administrator card.**
   To elevate privileges to an administrator session:
   - Copy the header, UID, and IV from `card_sam.bin`.
   - Modify the role byte at Page 8, byte 1 from `0x01` to `0x03` (`ADMIN`).
   - Update the username field to `"admin"` with length `5`.
   - Recompute the big-endian CRC-32 over `\text{UID} \mathbin{\Vert} \text{timestamp} \mathbin{\Vert} \text{0x03}`.
   - Store the updated CRC-32 into Page 16 (offsets 40–43).
   - Re-encrypt the 136-byte payload (bytes 24–159) with 3DES-CBC using key `BREAKMEIFYOUCAN!` and the original IV.
   - Write the forged 192-byte card image.

6. **Validate at the checkpoint.**
   POST the forged binary file as multipart form-data to `/api/validate` on the challenge instance. The validator decrypts the image, confirms the CRC-32 signature, checks administrator status, and grants gate entry.

## Answer

Submitting the forged administrator card image to the validation checkpoint returns:
`CSCTF{Veu9tlx1Sl463KuLZ2vqWuSy}`

## Notes

When parsing the UID, remember that MIFARE Ultralight C stores 7-byte serial numbers across the first two pages separated by manufacturer check bytes: byte 3 is BCC0 and byte 8 is BCC1. The CRC-32 input requires only the raw 7-byte identifier.

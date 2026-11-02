# GhostBus

Hardware, 58 points, 337 solves. A smart-lock sensor hub was pulled from a decommissioned site. The secure element is locked, but a field engineer probed the internal UART bus between the MCU and the secure element, and separately dumped the external SPI NOR flash. The flash also holds a recovery copy of the MCU firmware, which is supplied separately as an ELF. The whole challenge is offline: recover the nonce the secure element hands out, reverse the firmware's key derivation, and open the sealed 48-byte record.

## What you are given

`ghost_bus.zip` expands to three artifacts:

```
capture.csv       two-channel UART probe between MCU (ch0) and secure element (ch1)
flash_dump.bin    external SPI NOR dump, includes a firmware recovery copy
firmware.elf      ARMv7-M, stripped
```

No instance, no host, no login material. The description states two facts that matter later: the secure element returns the same nonce on every read, and reprovisioning replaces both the nonce and the sealed ciphertext. So it is not a random-number command and there is nothing to brute force.

## Reproduction

1. Recover the bus framing from the firmware, not from guesswork. The build routine is at `0x80001e8` and the parse routine at `0x8000278`. Frames are:

   ```
   AA 55 | len | cmd | payload | crc16
   ```

   with CRC-16 over `len|cmd|payload` and initial value `0xFFFF`. Knowing this lets you read `capture.csv` as a conversation rather than as hex.

2. Walk the capture. Channel `ch0_hub_tx` starts with a banner frame and then a zero-length request frame:

   ```
   AA 55 0C 01 "GB2.2 SE OK!" D5 C9
   AA 55 00 10 00 7C
   ```

   `cmd=0x10`, no payload. Channel `ch1_se_tx` answers with one frame:

   ```
   AA 55 10 10 <16 bytes> F3 E2
   ```

   The 16-byte payload is the provisioned nonce:

   ```
   9e3b7a44c1d05f82a6e1b4907cd3f5a2
   ```

   That single frame is the disclosure the vendor thought was protected. Command `0x10` is a read of a stored value, not an authentication, so the probe captures it in the clear.

3. Survey the flash before touching crypto. Three regions matter:

   ```
   0x68000  48-byte record, then ASCII "SEALED v1 rotated out"
   0x6A000  48-byte record, then ASCII "SEALED v2 addr=0x6A000 len=48"
   0x7F000  metadata: "GB-HUB-01 rev C / fw=2.2.0 / sealed=0x6A000 len=48"
   ```

   The metadata names the live record by address and length, so there is no ambiguity about which of the two ciphertexts is current. The `0x68000` record belongs to an earlier provisioning.

4. Read the firmware's reset handler at `0x8000380`. The sequence is short and unambiguous:

   - `0x800039e` reads the secure element, `0x80003f2` receives the frame and accepts only `cmd=0x10` with a 16-byte payload.
   - `0x800044c` SHA-256 init, `0x8000452` updates with 24 bytes at `.rodata+0x0C` (`0x8000ca0`), `0x800045c` updates with the 16-byte nonce, `0x8000466` finalises to 32 bytes.
   - `0x80004d2` sets up AES with `key = digest[0:16]` and `iv = nonce`. The copy is at `0x8000b5e`, 16 bytes of key plus 16 of IV. `0x8000808` is a plain AES-128 key schedule, eleven round keys, so it is AES-128 and not AES-256.
   - `0x80004b4` reverses each 4-byte word of the 48-byte record before use, which is an endianness fix for a record stored word-swapped.
   - `0x8000bdc` is CBC decryption with the usual IV and previous-block chaining.

5. Note the salt. The 24 bytes at `0x8000ca0` are:

   ```
   04325a9c117f3da0c0ffee5aa55a00ff1234567890abcdef
   ```

   It is a static constant in the firmware image, which is also present in the flash dump as the recovery copy. There is no other secret in the derivation.

6. Run the derivation. With nonce `N` and salt `S`:

   ```python
   key = hashlib.sha256(bytes.fromhex(S) + bytes.fromhex(N)).digest()[:16]
   ct  = b"".join(flash[o:o+4][::-1] for o in range(0x6A000, 0x6A000+48, 4))
   pt  = AES.new(key, AES.MODE_CBC, bytes.fromhex(N)).decrypt(ct)
   ```

   The plaintext is the flag followed by seven `0x07` bytes.

7. Treat the firmware's own output checks as the confirmation. At `0x80004e0` through `0x800052a` it validates the decrypted buffer in exactly the way a flag is validated: the last byte is the PKCS#7 pad length and must be between 1 and 16, every pad byte must equal it, `}` must sit at index `47 - pad`, and the buffer must start with `hiCTF{`. That check passing is proof the key, the IV and the word swap are all correct. Nothing about the path was guessed.

8. Try the older record as a sanity check. Decrypting `0x68000` with the same nonce does not produce a valid record. It belongs to a previous provisioning and its nonce was replaced, so the derivation above does not apply to it, which is what the notes record. The metadata at `0x7F000` had already named `0x6A000` as the live address, so this is confirmation rather than a decision point.

## Why it works

The sealed record's confidentiality rests on two values: a nonce stored in the secure element and a salt held in the MCU firmware. Both are in the evidence. The nonce arrives on a two-wire bus that a probe can read, and the secure element serves it to any request with command `0x10` without authentication, so the "locked" element is only locked against command classes it does not implement. The salt is a fixed constant compiled into the MCU image, which is also mirrored in the external flash. Neither value is a secret; together they are the entire key schedule input.

The derivation itself is textbook (SHA-256 over salt and nonce, first 16 bytes as AES-128 key, nonce as IV, CBC), so there is no cryptographic weakness to exploit. The failure is key management: the only key material is stored on, or read from, hardware the attacker already has in hand, and the design assumes the bus between MCU and secure element is unobservable. The decoy record shows the designers did think about rotation, but the rotation only replaces the nonce and the ciphertext, not the method, so rotation does not help once the bus is tapped.

The local notes record the three flash addresses, the field names and the disassembly anchors, but not the rest of the flash layout and not any capture of the provisioning step. Nothing beyond the three addresses was needed.

## Flag

```
hiCTF{gh0st_bu5_uart_n0nc3_r3v3al_9c3f12}
```

# DefCamp CTF 2026: solstice-9 (Misc) - Writeup

## Challenge Overview
- **Category:** Misc
- **Points:** 460
- **Difficulty:** Hard
- **Author:** thek0der
- **Type:** deployment / kubernetes
- **Description:** "A solar controller was retired without explanation. Its field firmware survived, including archived bench captures. One static flag. Format: `DCTF{sha256}`"

## Architecture & Analysis

The challenge provides a 3.93 GiB disk image `solstice9-firmware.img`, which is an ARM64 (aarch64) Raspberry Pi system based on Solar-Assistant (built via `pi-gen`).

Inspecting the files modified at the challenge creation timestamp (`2026-09-15 09:05:10`) reveals the CTF additions:
- `/usr/sbin/powerd`: An RTU communication bridge daemon listening on a TCP socket.
- `/usr/libexec/boarddiag`: A diagnostic utility that verifies a 96-byte calibration fixture and prints its public identity.
- `/usr/share/board/storage.txt`: Documentation detailing the controller's SPI flash journal format and dewhitening algorithm.
- `/usr/share/board/fixture.txt`: Documentation detailing the fixture assembly specification and protocol.
- `/var/lib/powerd/archive/`:
  - `controller-spi.raw` (1,114,112 bytes): Raw SPI flash dump containing 4096 physical pages (256 data + 16 spare bytes each).
  - `capture-01.csv` (27,860 bytes): Logic analyzer capture of SCL and SDA lines on an eight-pin 24C02 serial EEPROM.
  - `capture-02.csv` (8,892 bytes): Logic analyzer capture of the supervisor UART line (inverted by a transistor).
  - `bench.txt`: Board metadata noting PCB marking `5319 / revision 0002`.

According to `fixture.txt`, the 96-byte calibration fixture is a concatenation of three 32-byte components in order:
1. Controller journal (32 bytes)
2. EEPROM calibration (32 bytes)
3. Supervisor packet (32 bytes)

### 1. Component 1: Controller Journal (32 bytes)
From `storage.txt`:
- 4096 pages, each 256 data bytes + 16 spare bytes.
- Dewhitening: $x_0 = 0\text{x9e3779b9} \oplus \text{page\_index}$.
  For each data byte: $x \leftarrow x \oplus (x \ll 13)$, $x \leftarrow x \oplus (x \gg 17)$, $x \leftarrow x \oplus (x \ll 5)$ (all operations 32-bit unsigned), then $\text{data} \oplus (x \ \& \ 0\text{xff})$.
- Spare format: `magic[2], kind:u8, flags:u8, generation:u16, length:u16, board_rev:u32, crc32:u32`.
- Standard CRC32 over `spare[0:12] + dewhitened_data`.
- Flags bit 0 (`flags & 1`) indicates a committed record.
- Kinds `0x31` and `0x32` form a paired $16 + 16$ byte component matching `board_rev = 0x53190002`.
- Filtering for committed pages matching revision 2 and maximum generation counter yields generation 2:
  - Kind `0x31` (Page 3134): `f07fb429318b400792c47765179ff564`
  - Kind `0x32` (Page 67): `02ad956f22989e77868b65099f095d66`
- Component 1: `f07fb429318b400792c47765179ff56402ad956f22989e77868b65099f095d66`.

### 2. Component 2: EEPROM Calibration (32 bytes)
From `capture-01.csv` and `fixture.txt`:
- Probes monitor 24C02 I2C EEPROM at slave address `0x50`.
- Rev 2 calibration resides at offset `0x40` (32 bytes).
- Parsing I2C transactions:
  - Offset `0x40` (16 bytes): `3fefc049a89a612a3542d30ecc3952c4`
  - Offset `0x50` (16 bytes): `b4171fe14e33a98c0dbad42301529530`
- Component 2: `3fefc049a89a612a3542d30ecc3952c4b4171fe14e33a98c0dbad42301529530`.

### 3. Component 3: Supervisor Packet (32 bytes)
From `capture-02.csv`, `bench.txt`, and `fixture.txt`:
- Probe on `ch0` monitors UART TX inverted by a transistor.
- Bit period is $17,361\text{ ns}$ ($57,600\text{ baud}$).
- Since the transistor inverts the signal: idle is 0, start bit is 1, data bits are inverted ($1-b$), stop bit is 0.
- Decoded stream reveals three packets with header `55 aa`:
  - Packet 1: Revision 1, CRC valid.
  - Packet 2: Revision 2, CRC16/Modbus (`0xcc6c`) matches calculated CRC!
  - Packet 3: Revision 2, CRC mismatch (corrupt/noise packet, per hint: "not the last packet seen").
- Valid Revision 2 packet data (32 bytes):
  - Component 3: `6c8737ba4c7a107a4c01f44dc0f42df58a36735d3aca1bcaba67191ffea05225`.

---

## Key Derivation & Self-Verification

`boarddiag` mixes the 96-byte fixture through an 8-bit rotation and byte permutation loop to produce a 32-byte Ed25519 private seed:
- Private Key: `1dafdc419cd8a71b9b0041d4b856ab9f36322592cc14e09f1172a215c58d7d11`
- Derived Ed25519 Public Key:
  `8bc22f9dad276d4302d75f5bf0dc6ab30a50ff102d9d7b96de69fec36048ed4c`

This derived public key matches the hardcoded authorization public key at offset `0x1f30` in `powerd` byte-for-byte.

---

## Remote Protocol Exploitation

`powerd` runs a Modbus/RTU transport bridge over TCP:
1. **Challenge Request (FC 0x41):**
   - Payload: Unit ID (`0x17`) + FC (`0x41`) + Board/Rev (`0x53190002` -> `53 39 00 02`) + CRC16/Modbus.
   - Command: `XFER 1741533900027fbb\n`.
   - Response: `174120<32-byte nonce><CRC16>`.
2. **Maintenance Authentication (FC 0x42):**
   - Message to sign: `b"SOLSTICE9/maintenance/v1" + nonce` (56 bytes).
   - Sign with Ed25519 private key to get 64-byte signature.
   - Payload: Unit ID (`0x17`) + FC (`0x42`) + Signature (64 bytes) + CRC16/Modbus.
   - Command: `XFER 1742<signature_hex><crc_hex>\n`.
3. **Flag Response:**
   - Server validates Ed25519 signature against its stored public key, then responds with FC 0x42 returning the flag.

---

## Flag
`DCTF{c7da32e39bd5727769742639fb9855971cb88cb952573182913b9155d7b1b286}`

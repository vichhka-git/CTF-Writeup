# grid-watch

**Category:** Network · **Points:** 551 · **Flag:** `CSCTF{iAAHnF9Nt8CdYEl8fW2HAUQ2}`

## What the handout gives you

The handout contains a telemetry capture from an inspection drone alongside field engineering documentation:

- `capture.tlog` (1,370 bytes) — binary MAVLink 2 telemetry log recording communications between a ground station and an aerial patrol unit.
- `provisioning_note.md` (1,217 bytes) — internal engineering memo detailing MAVLink 2 signing rules, clock calibration, and key re-provisioning specifications.

## Walkthrough

1. **Review the airframe provisioning specifications.** Reading `provisioning_note.md` reveals that the CX-series drone enforces MAVLink 2 packet signing for all flight commands. The pre-shared flight signing key is never transmitted on the link. However, field units support dynamic key re-provisioning via a `SETUP_SIGNING` packet (MAVLink message ID 256), authenticated by a provisioning key:
   `prov_key = HKDF-SHA256(ikm = serial_ascii || commissioning_epoch, salt = session_nonce, info = "CX-PROV/v1", L = 32)`
   Here, `commissioning_epoch` is a 64-bit little-endian integer counting seconds from the Unix epoch, and `session_nonce` is announced by the drone upon initial TCP connection.

2. **Extract airframe identity from telemetry.** Parse the packet stream in `capture.tlog`. Each entry begins with an 8-byte big-endian microsecond Unix timestamp, followed by a standard MAVLink 2 frame (`0xFD` magic byte). Message ID 253 (`STATUSTEXT`) contains the ASCII broadcast:
   `CX-FALCON-9951 online, patrol LEA-220-VEST`
   This identifies the airframe serial string as `CX-FALCON-9951`.

3. **Determine the commissioning epoch.** The engineering memo states that the 48-bit timestamp in the MAVLink 2 signature represents 10 µs RTC ticks elapsed since the airframe's commissioning epoch. In `capture.tlog`, the first signed packet has an external capture timestamp of `1756783327` seconds (`1756783327000000` µs) and an internal signature timestamp of `2281859190947` ticks:
   - Converting ticks to elapsed seconds: `2281859190947 \times 10^{-5} \approx 22818591.9` seconds.
   - Subtracting elapsed time from the capture timestamp: `1756783327 - 22818591.9 \approx 1733964735.1` seconds.
   - Evaluating tick progression and RTC clock drift across the entire log narrows the integer commissioning epoch to `1733965123` (2024-12-12 01:25:23 UTC).

4. **Connect to the live instance and acquire the session nonce.** Establish a TCP connection to the target airframe service. The drone immediately transmits unauthenticated `STATUSTEXT` frames containing the session salt:
   `PROV NONCE <hex_string>`
   Convert the 32-character hexadecimal string into a 16-byte raw binary salt. Record the latest signature timestamp (`last_ts`) from accompanying signed telemetry frames to ensure outgoing timestamps satisfy replay-prevention monotonicity.

5. **Derive the provisioning key.** Construct the input key material:
   `ikm = b"CX-FALCON-9951" + struct.pack("<Q", 1733965123)`
   Execute HKDF-SHA256 with `salt = session_nonce` and `info = b"CX-PROV/v1"` to generate the 32-byte `prov_key`.

6. **Re-provision the link signing key.** Construct a `SETUP_SIGNING` packet (message ID 256):
   - Target system: `1`, target component: `1`.
   - Initial timestamp: `last_ts + 1000`.
   - Key: An arbitrary 32-byte secret known to the operator.
   Sign the packet using `prov_key` per MAVLink 2 signing rules (calculating a truncated 48-bit SHA-256 digest over the key, header, payload, CRC-16, link ID, and timestamp). Transmit the packet over the TCP socket. The airframe verifies the provisioning key and activates the new signing key.

7. **Execute flight control sequence.** The drone remains in `LOITER` until reconfigured. Using the newly provisioned key, assemble and sign three consecutive `COMMAND_LONG` (message ID 76) packets:
   1. Mode change: Command `176` (`MAV_CMD_DO_SET_MODE`) with custom mode `4` (`GUIDED`).
   2. Motor arming: Command `400` (`MAV_CMD_COMPONENT_ARM_DISARM`) with param1 = `1` (arm).
   3. Reposition: Command `192` (`MAV_CMD_DO_REPOSITION`), assigning new corridor coordinates.

8. **Read execution confirmation.** Upon receiving and authenticating the signed reposition order, the drone executes the command and emits a `STATUSTEXT` telemetry message confirming the waypoint diversion.

## Answer

The airframe accepts the authenticated reposition order and responds over the command socket with the flag:

`CSCTF{iAAHnF9Nt8CdYEl8fW2HAUQ2}`

## Notes

MAVLink 2 packet signatures include a 16-bit X.25 CRC value that requires a message-specific seed byte (`crc_extra`). For `SETUP_SIGNING` (ID 256), `crc_extra` is 71; for `COMMAND_LONG` (ID 76), `crc_extra` is 152. Calculating the CRC with incorrect seed constants invalidates the frame before the signature is ever evaluated.

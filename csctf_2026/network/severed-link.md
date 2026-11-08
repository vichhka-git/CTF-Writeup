# Severed Link

**Category:** Network · **Points:** 200 · **Flag:** `CSCTF{smxRDYl5vMnNk6YPWZkCCviU}`

## What the handout gives you

The handout arrives as `severed-link.zip`, containing a network capture, a telemetry log, and operator incident notes. The challenge also provides a live TCP uplink gateway simulating the aircraft field station.

- `mission.pcap` — 11,048-byte network capture of UDP port 14550 traffic between ground operator 10.42.0.11 and drone 10.42.0.1.
- `mission.tlog` — 5,674-byte binary MAVLink telemetry log recorded during the mission.
- `ops_notes.txt` — 920-byte text note explaining that the link uses MAVLink 2 with per-frame signing, the operator is system ID 255, the drone is system ID 1, and the secret signing key was rotated in-band across the recorded link.

## Walkthrough

1. **Locate the in-band key rotation.** The incident note reports that the operator pushed a new signing key over the active mission link. In MAVLink 2, signing setup uses message ID 256 (`SETUP_SIGNING`). Filtering the telemetry log or the packet capture reveals the rotation packet.

```bash
mavlogdump.py mission.tlog --types SETUP_SIGNING
```

The output shows message 256 sent from system 255 (component 190) to system 1 (component 1). The payload contains the 32-byte secret signing key `8f2b4e71a6c3d05f9217bc84e63a1d57f0482c6b9e13a7d5c84f26019bd3ea60` and `initial_timestamp: 2295`.

2. **Understand MAVLink 2 frame signing.** A signed MAVLink 2 packet begins with packet magic `0xFD`, the payload length, incompatibility flag `0x01` (denoting a signature block), compatibility flags, sequence number, system ID, component ID, and a 3-byte message ID. After the payload and a 2-byte CRC-16, a 13-byte signature trailer is appended. This trailer contains a 1-byte link ID (`0x00`), a 6-byte little-endian timestamp (in 10-microsecond increments), and a 6-byte cryptographic signature. The signature is the first 6 bytes of `SHA256(secret_key + header + payload + crc + link_id + timestamp)`.

3. **Sample the live stream timestamps.** The live TCP gateway implements replay protection: it tracks the highest timestamp received on the link and rejects any frame whose timestamp does not strictly increase. Connect to the service over TCP to read the telemetry stream.

```bash
nc <host> <port>
```

The station immediately streams signed telemetry packets (`STATUSTEXT`, `HEARTBEAT`). Extracting the 6-byte timestamp field (bytes -12 to -6 of incoming frames with incompatibility flag bit 0 set) provides the current baseline timestamp used by the station.

4. **Send an authenticated operator heartbeat.** Sending a flight command directly fails because the drone firmware enforces an active operator session before accepting control actions: `REJECTED: send a HEARTBEAT first.` Craft a signed `HEARTBEAT` message (message ID 0) from system ID 255 and component ID 190. Set the timestamp to a value strictly higher than the current stream timestamp, sign the frame with the recovered 32-byte key, and transmit it over the TCP connection.

5. **Send a signed reposition command.** Once the heartbeat is accepted, issue an operational command to redirect the drone. Send a signed `COMMAND_INT` frame (message ID 75) targeted at system 1, component 1 with command `DO_REPOSITION` (command code 192), incrementing the sequence number and timestamp.

## Answer

Upon receiving the validly signed reposition command from the authenticated operator identity, the station executes the command and emits a signed `STATUSTEXT` audit entry containing the flag:

`CSCTF{smxRDYl5vMnNk6YPWZkCCviU}`

## Notes

The gateway requires two sequential conditions that can trip up an attacker. First, timestamps must strictly advance; submitting a static timestamp or replaying recorded frames fails validation. Second, the ground station requires an initial operator `HEARTBEAT` from system 255 / component 190 before it will process `COMMAND_INT`.

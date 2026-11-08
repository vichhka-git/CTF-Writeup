# Split Horizon

**Category:** Reverse engineering · **Points:** 450 · **Flag:** `CSCTF{kLxrzB1a9GGbXpMcS574A8ur}`

## What the handout gives you

A collection of operational flight logs and software binaries from an aerial reconnaissance incident:

- `session.pcap` (16,583 bytes) — packet capture containing the encrypted command-and-control uplink stream.
- `vireo-ctl.dll` (9,728 bytes) — .NET assembly running on the UAV flight controller.
- `command-server.go` (5,637 bytes) — Go source code for the ground station dispatch server.
- `manifest.json` (323 bytes) — mission profile parameters: approved waypoint (latitude 46.4975, longitude 23.7128), altitude 5500 m, tolerance 0.001 degrees.
- `audit.log` (1,664 bytes) — cryptographic audit trail recording SHA-256 hash chains signed with Ed25519.
- `sigint.txt` (507 bytes) — mission briefing confirming the drone diverged hundreds of meters off course despite nominal server logs.

## Walkthrough

1. **Extract shared secret from the drone controller.**
   Inspect `vireo-ctl.dll` with an IL decompiler or disassembler. The assembly implements transport security for flight commands. Two static byte arrays, `MaskA` and `MaskB` at RVAs `0x3ba8` and `0x3bc8`, combine via XOR to establish the 32-byte pre-shared secret:
   `a75360e209604f27ddb53bd4f640894e8719810daa342219a8ac8e8551879a51`

2. **Decrypt uplink frames.**
   Examine `session.pcap`. The capture records an initial handshake exchanging 16-byte client and server nonces, followed by encrypted command frames. Computing HMAC-SHA256 over the concatenated nonces using the 32-byte pre-shared secret derives the 16-byte session key. Decrypting the payload blocks with AES-CBC unmasks the raw JSON flight command sequence.

3. **Inspect decrypted commands against server audit logs.**
   The audit log records nominal coordinates for sequence numbers 1 through 5. Comparing decrypted JSON objects against `audit.log` reveals an anomaly in command sequence 3:
   `{"seq":3,"waypoint_lat":46.4965,"waypoint_lon":23.7166,"WAYPOINT_LAT":46.4966,"WAYPOINT_LON":23.7122}`
   The command contains duplicate coordinate keys with differing case.

4. **Analyze parser differentials.**
   - **Ground Server (`command-server.go`):** The server parses JSON using Go's `encoding/json` package. In Go, unmarshaling performs case-insensitive key matching against struct tags. When duplicate matching keys appear, Go preserves the last occurrence. The server read `"WAYPOINT_LAT": 46.4966` and `"WAYPOINT_LON": 23.7122`. Because these values fall within the 0.001-degree tolerance of the approved target (46.4975, 23.7128), the server logged the waypoint as nominal and appended it to the signed audit ledger.
   - **UAV Controller (`vireo-ctl.dll`):** The flight controller is a .NET assembly utilizing `System.Text.Json`. Unlike Go, .NET's serializer is case-sensitive by default. It matched the exact lowercase fields `"waypoint_lat"` and `"waypoint_lon"`, discarding the uppercase entries. Consequently, the drone navigated to latitude `46.4965` and longitude `23.7166`.

5. **Quantify flight divergence.**
   Calculating the geographical distance between nominal coordinates `(46.4966, 23.7122)` and the executed position `(46.4965, 23.7166)` reveals a lateral shift of approximately 340 meters East. This accounts for the observed trajectory drift while leaving the ground server's audit chain valid.

6. **Submit attribution parameters.**
   POST the attribution payload to the `/submit` endpoint specifying the compromised command sequence (`3`), the coordinates executed by the UAV (`46.4965`, `23.7166`), and the parser differential vulnerability class.

## Answer

Submitting the verified attribution report returns the incident confirmation token:
`CSCTF{kLxrzB1a9GGbXpMcS574A8ur}`

## Notes

The attack exploited parser divergence between Go's standard library JSON decoder (case-insensitive, last-key-wins) and .NET's `System.Text.Json` (case-sensitive, first exact match). This permitted the adversary to pass strict ground-station bounds checks while steering the UAV off its flight path.

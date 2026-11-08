# Operation Blackout

**Category:** ICS · **Points:** 900 · **Flag:** `CSCTF{12fcdb0d}`

## What the handout gives you

Five artifacts describing one incident at substation `0x4A2E`: a SCADA capture
(`scada_network.pcap`), the HMI configuration (`hmi_config.xml`), the PLC firmware
(`plc_firmware.bin`), the event log (`substation_log.json`) and the alarm override table
(`alarm_override.dat`).

The brief is explicit that the marker is derived from the parts the evidence agrees on,
and the flag is eight lowercase hex characters — a truncated hash, not a string hidden
in a file.

## Walkthrough

1. **Read the log first.** It gives the incident timeline. A normal start at
   `06:00:00Z` carries `manifest_seed: 137`. At `06:15:00Z` the HMI loads
   `Q3_Equipment_Calibration.xml`; three seconds later the PLC logs an unexpected
   Modbus function-code 16 write to read-only registers `40001-40064`; then alarm
   thresholds change, traffic leaves for `198.51.100.42:443`, the firmware integrity
   check fails, and the substation goes dark.

2. **Read the configuration.** `hmi_config.xml` names the station `0x4A2E`, the
   calibration routine `Q3_Equipment_Calibration`, the seed `137`, the target
   `192.168.50.10:502`, three setpoint registers, and one hidden write: function code
   16, start address `40001`, count 64, payload `55 FA` repeated eight times.

3. **Walk the capture.** The pcap holds thirty identical function-code 3 reads of
   register `0x9C41` (40001), one function-code 16 write to the same register with a
   64-register count and the `55FA` payload, and five outbound HTTP posts to
   `198.51.100.42` on port 80 carrying `DE AD` filler.

4. **Read the firmware.** The first bytes are `PLC1` followed by a version string
   `3.2.1`. Two XOR windows hide text: one spells `SCADA BLACKOUT`, the other spells
   `scada_blackout_2026`. The organiser's note that this string is a decoy is correct —
   it is not part of the marker.

5. **Read the overrides.** `alarm_override.dat` starts with `ALRM`, a version, the
   station id, then three records of the form `{address, old value, new value, name}`.
   The addresses are `40100`, `40101` and `40102`; the value changes are 85→250,
   200→10 and 500→5000, matching the log entry.

6. **Separate what agrees from what does not.** Three apparent corroborations are
   traps. The log says port 443; the capture shows port 80. The log says a 247-byte
   overflow; the write frame is 29 bytes. The capture's write timestamp is 06:05:03Z;
   the log's is 06:15:03Z. None of those three values can be part of the answer.

7. **Assemble the five values the artifacts do agree on.**

   - firmware identification: the first four bytes `PLC1`, written as `0x504C4331`
   - station id: `0x4A2E`
   - timestamp of the malicious write, from the log: `2025-11-15T06:15:03Z`
   - start register, in decimal: `40001`
   - calibration seed, in decimal: `137`

8. **Hash them.** Join with single colons, in that order, no trailing separator, and
   take the SHA-256. The first eight hex characters of the digest are the flag body.

## Answer

The preimage is

`0x504C4331:0x4A2E:2025-11-15T06:15:03Z:40001:137`

and `CSCTF{12fcdb0d}` is the first eight hex characters of its SHA-256 digest.

## Notes

The order and the formatting matter more than the parsing. The firmware id is the
first four bytes as a big-endian hex value with lowercase `0x` prefix, the station id
keeps the `0x` prefix from the artifacts, the timestamp keeps the ISO `T` and `Z`, and
both numbers are plain decimal. Padding, uppercase hex or reordered fields all give a
wrong digest.

The decoy string in the firmware is a good reminder to hash only values that two
independent artifacts support.

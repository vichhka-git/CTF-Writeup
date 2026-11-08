# Phantom Drift

**Category:** Forensics · **Points:** 900 · **Flag:** `CSCTF{5dc7cdf826f74515}`

## What the handout gives you

Six files from a UAV incident: `flight_log.bin`, `mission_manifest.json`,
`telemetry_logs.json`, `radio_intercept.log`, `command_backend.decompiled` and
`drone_control.decompiled`. The last two are base64-wrapped source listings — one Go,
one C# — for the two halves of the command path.

The flag is the first sixteen hex characters of a SHA-256 digest. A tag stored in the
flight log is the *last* eight characters of the same digest and serves as an offline
check on your input.

## Walkthrough

1. **Read the manifest.** The approved waypoint is `47.2591, 19.0402`, the surveillance
   zone is centred on it, and the aircraft is `Valkyrie-X9`. This is what the mission
   was supposed to do.

2. **Read the telemetry.** The `waypoint_update` record carries the same values twice:
   lowercase `waypoint_lat`/`waypoint_lon` with `47.2591`/`19.0402`, and PascalCase
   `WaypointLat`/`WaypointLon` with `47.26`/`19.045`. Everything else in the record
   (`altitude`, `speed`, `payload_weight`, `wind_compensation`) is duplicated the same
   way with identical values, which is why the packet looks harmless at a glance.

3. **Read both parsers.** The Go side tags its struct fields
   `json:"waypoint_lat"` and `json:"waypoint_lon"`. When a struct has a tag, Go matches
   the tag name and ignores the others, so Go reads the lowercase pair and validates
   `47.2591, 19.0402` against the manifest with a 0.001 tolerance — and passes. The C#
   side disables case-insensitive matching and treats unknown members as errors, so it
   also reads the lowercase pair.

4. **Notice the mismatch anyway.** The drone physically flies to `47.26, 19.045`: the
   `waypoints_visited` summary lists that pair as the surveillance target, and the
   radio transcript has the ground station reporting the aircraft 380 m east of the
   planned point. The parsers agree with the manifest; the aircraft does not agree with
   the parsers.

5. **Decode the flight log.** It is 36 bytes: magic `FLGT`, version 1, a record count
   of 3, a record size of 12, then records. Only two exist. The second is XOR-encrypted
   with the mission id `Valkyrie-9` and decodes to `TAG:dc6836a2` — the check value.

6. **Build the digest input from what the mismatch produced.** The values are the
   approved position, the actual position's offset, and the distance between them, all
   with fixed formatting and no separators:

   - approved latitude and longitude to four decimals: `47.2591`, `19.0402`
   - latitude and longitude delta to six decimals: `+0.0009` → `0.000900`,
     `+0.0048` → `0.004800`
   - great-circle displacement to one decimal: `376.2` m

   The displacement uses the haversine formula with the WGS-84 equatorial radius
   6 378 137 m. With a mean Earth radius the value comes out 375.8 m and the hash does
   not match.

7. **Hash and verify.** Concatenate in that order —
   `47.259119.04020.0009000.004800376.2` — and take the SHA-256. Its first sixteen hex
   characters are the flag; its last eight are `dc6836a2`, which is exactly the tag in
   the flight log. That is the confirmation the challenge is telling you to look for.

## Answer

`CSCTF{5dc7cdf826f74515}`

## Notes

The tag is only 32 bits, so unrelated inputs collide with it constantly. Finding a
string that hashes to `dc6836a2` at the end proves nothing on its own; the tag exists to
check the input you derived from the evidence, not to be brute-forced. The same applies
to the flag: the first sixteen hex characters are the answer, and the tag is a suffix of
the same digest.

Formatting is the whole challenge. Four decimals for the approved point, six for the
deltas with no `+` sign, one for the distance, no separators, and a latitude/longitude
order that matches the manifest's reading order.

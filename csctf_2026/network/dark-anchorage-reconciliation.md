# Dark Anchorage Reconciliation

**Category:** Network · **Points:** 270 · **Flag:** `CSCTF{lTDSpLMfFB2bQ5EJC2AJdHxN}`

## What the handout gives you

A live challenge instance exposing maritime sensor evidence and reconciliation endpoints:

- `GET /files/ais.ndjson` (260,639 bytes) — newline-delimited JSON stream of coastal Automatic Identification System (AIS) transponder broadcasts.
- `GET /files/radar.csv` (100,201 bytes) — radar observation logs recording track identifiers, local timestamps, range, and coordinates.
- `GET /files/cable-fault.txt` (286 bytes) — location and timing parameters of the KALNET-1 physical cable fault.
- `GET /files/method-note.txt` (985 bytes) — sensor normalization equations, projection parameters, and reporting criteria.
- `GET /schema` (1,518 bytes) — JSON schema required for the submission endpoint at `POST /reconcile`.

## Walkthrough

1. **Inspect cable fault parameters and instructions.**
   Downloading `cable-fault.txt` specifies the fault position at latitude `49.87843677`, longitude `19.92413173`, with an observed disruption window from `2026-11-06T10:20:00Z` to `2026-11-06T10:34:00Z`.
   Reading `method-note.txt` establishes the mathematical procedure:
   - Normalize radar time: subtract the signed header offset `radar_utc_offset_minutes` (-120 minutes) to convert local radar clocks to UTC.
   - Coordinate projection: project geographical coordinates to a local flat plane centered at the cable fault origin using spherical radius `R = 6,378,137` meters.
   - Projection equations:
     `x = R \cdot \cos(\text{lat}_0) \cdot (\text{lon} - \text{lon}_0)`
     `y = R \cdot (\text{lat} - \text{lat}_0)`

2. **Normalize timestamps and project sensor data.**
   Parse `ais.ndjson` and `radar.csv`. Subtracting -120 minutes from radar records (adding 2 hours) aligns the radar timeline directly with UTC AIS records. Projecting all positions into Cartesian coordinates `(x, y)` yields metric displacements relative to the cable fault origin `(0, 0)`.

3. **Construct track-to-vessel bijection.**
   For every combination of radar track and AIS vessel MMSI, compute the Euclidean distance residual between observations recorded at the same UTC seconds. Evaluating the median residual across shared timestamps separates genuine matches from cross-track pairings:
   - Genuine associations have a median residual distance `\le 35` meters.
   - False associations yield median residuals `\ge 180` meters.
   This provides a complete, unambiguous 16-to-16 bijection matching all coastal radar tracks to their corresponding maritime transponders.

4. **Isolate the anomalous track and spoofing displacement.**
   Scanning all matched pairs against rule 7 of `method-note.txt` isolates track `R-07`, corresponding to MMSI `970725350`:
   - It contains a contiguous sequence of 5 samples where the spatial residual between radar and AIS exceeds 250 meters.
   - The offset vector remains stable, varying by less than 15 meters between consecutive points.
   - Averaging the residual components across this anomaly window produces a deliberate displacement of approximately `+330` meters East and `-330` meters North.
   The vessel was spoofing its AIS position southeast of its actual physical track to appear clear of the restricted cable corridor.

5. **Calculate Closest Point of Approach (CPA).**
   Using physical radar track positions from `R-07`, evaluate line-segment distances to the cable fault origin `(0, 0)`.
   For segment points `p` to `q`, the projection scalar is:
   $u = \text{clamp}\left(-\frac{p \cdot (q - p)}{(q - p) \cdot (q - p)}, 0, 1\right)$
   At timestamp `2026-11-06T10:31:38Z`, the calculated distance between radar track `R-07` and the cable fault origin reaches exactly `0.0` meters. The vessel passed directly over KALNET-1 during the recorded fault interval.

6. **Submit reconciliation report.**
   Assemble the JSON report containing the 16 bijection pairs, anomalous track `R-07`, spoofed vessel `970725350`, spoofing displacement vector, and CPA parameters (`cpa_utc_time: "2026-11-06T10:31:38Z"`, `cpa_distance_m: 0.0`). Transmitting the payload to `POST /reconcile` returns the validation grant.

## Answer

Submitting the verified reconciliation report to `/reconcile` returns the incident resolution token:
`CSCTF{lTDSpLMfFB2bQ5EJC2AJdHxN}`

## Notes

The radar timestamps carry a negative UTC offset in the CSV metadata header (`# radar_utc_offset_minutes: -120`). Because `local_time = UTC + offset`, standard normalization requires subtracting `-120` minutes (effectively advancing the timestamp by 2 hours) to synchronize with AIS.

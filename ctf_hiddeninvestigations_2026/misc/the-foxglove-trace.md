# The Foxglove Trace

The Foxglove Trace was a 54 point misc challenge (603 solves in the local record). It is an offline data puzzle about a half finished personal project: a hobbyist wanted to work out which place they kept returning to by combining step counter deltas with Wi-Fi signal readings. Four files survive, two numbers in the scoring rule are missing, and the run log pins both of them.

## What you are given

- `abandoned-tracker.zip` with four files: `notes.txt`, `aps.conf`, `scan_export.csv`, `run.log`.
- `aps.conf` lists four trusted access points with integer trust weights, and says everything else in the scan is ignored.
- `scan_export.csv` has 33 data rows with `timestamp,ap_name,signal,step_delta`.
- `run.log` is the verbose output of the one run that worked, filtered to two access points, with per row kept or dropped decisions and per AP subtotals.

No service, no host, no credentials. Nothing to connect to.

## Reproduction

1. Read `notes.txt` for the shape of the rule. It says a place that matters shows up as the person physically moving near the same access point again and again, that a strong signal alone means proximity and not travel, that stationary readings are noise, and that the trusted access points in `aps.conf` carry more weight than random hotspots. It deliberately omits the movement cutoff and says to recover it from the log.

2. Read `aps.conf`. The trusted set and weights are `FoxgloveCoffee_Guest=3`, `HomePlex_5G=2`, `CafeDelMundo=2`, `NETGEAR-8841=1`. Five other names appear in the scan (`xfinitywifi`, `Starbucks`, `AndroidAP_2931`, `ATT-WiFi-5521`, `linksys`) and are not considered at all.

3. Use `run.log` to pin the movement cutoff. For CafeDelMundo it prints:

   ```
   signal=62  step_delta= 40  -> stationary, dropped
   signal=58  step_delta= 41  -> moving, kept
   ```

   The boundary sits exactly between 40 and 41, and 40 is dropped while 41 is kept, so the rule is `step_delta > 40`.

4. Use the same log to pin the per access point score. CafeDelMundo has weight 2 and three kept readings, 58, 60 and 64, and the log prints `subtotal = 364`. That is `2 * (58 + 60 + 64)`. HomePlex_5G also has weight 2, one kept reading of 87, and prints `subtotal = 174`, which is `2 * 87`. So the score is the sum of `signal * weight` over kept rows, with no constant offset and no logarithm term.

   The log also states `(7 more rows dropped)` for HomePlex_5G, and the export has 10 HomePlex rows, so 3 shown plus 7 dropped accounts for all of them.

5. Apply the rule to the whole export. Keep a row when the trusted AP matches `aps.conf` and `step_delta > 40`, then sum `signal * weight`.

   ```
   FoxgloveCoffee_Guest  w=3  kept 68, 71, 66, 73, 70     348 * 3 = 1044
   CafeDelMundo          w=2  kept 60, 64, 58             182 * 2 =  364
   NETGEAR-8841          w=1  kept 80, 78, 82             240 * 1 =  240
   HomePlex_5G           w=2  kept 87                      87 * 2 =  174
   ```

   The highest score is `FoxgloveCoffee_Guest`. The local solution note prints step delta values in the signal column of its results table; the CSV signal values above are the ones that produce the recorded subtotals, and both checked totals (364 for CafeDelMundo, 174 for HomePlex_5G) match the log exactly.

6. Confirm the decoys are neutralised rather than just losing. The loudest trusted access point in the export is HomePlex_5G, with ten readings between 87 and 94. It is also the most frequent, with 10 of the 33 rows. Both traps in the description point at the same AP, and it finishes last because the phone is sitting at home: nine of its ten rows have step deltas of 3 to 22 and are dropped. The single row that survives has `step_delta=44` and a much weaker signal of 87.

   The untrusted `xfinitywifi` rows are actually the strongest in the file at 96, 94 and 93. They are discarded before scoring, which is what the trusted list is for.

7. Check the cutoff is not a magic number fitted to the answer. Sweeping the threshold from 0 to 100, `FoxgloveCoffee_Guest` wins for every cutoff from 5 to 90 inclusive. Only a cutoff of 0, meaning no movement filter at all, flips the winner to HomePlex_5G. That is the intended failure mode: without the movement filter the loudest AP wins, and the file is built so that the loudest AP is the wrong answer.

8. Spell the answer exactly as the access point appears in `aps.conf` and the export, including the underscore and the capital letters: `FoxgloveCoffee_Guest`. Submit it as `hiCTF{FoxgloveCoffee_Guest}`.

The local notes record the cutoff, the scoring form, the per AP totals and the winning name. They do not record a separate per row calculation trace beyond the two APs the log covers.

## Why it works

The intended rule is a product of two independent observations, and the surviving log prints enough intermediate state to solve for both without guessing. A dropped row and a kept row one step apart fix the threshold. A subtotal equal to `2 * (58 + 60 + 64)` fixes the formula, and it rules out additive offsets, log scaling, and row count weighting in one line.

The dataset is then arranged so that the naive signals point the wrong way. Signal strength measures proximity, so the home router is loudest while contributing nothing. Frequency measures how often the phone saw an AP, so the home router also wins that. Only the movement filter separates a place the person walks through from a place the person sits, and only the trust weights stop a random strong hotspot from taking the top spot. The design flaw being probed is the hobbyist's own blind spot: they kept tuning the cutoff, so the value is not in the notes, but one honest run logged enough to recover it.

## Flag

```
hiCTF{FoxgloveCoffee_Guest}
```

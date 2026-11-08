# Operation Dawn: Watch List Audit

**Category:** Misc · **Points:** 120 · **Flag:** `CSCTF{114ca27d8c3e02e5ec872dd02b83707cae245e2f07dadaa622867cf9b3894287}`

## What the handout gives you

The handout contains an archive with observation logs from a screening service scoring system and a specification document.

- `watch-list-audit.zip` — a 57 KB ZIP archive holding numerical data exports and documentation.
- `README.txt` — specification describing the model equation, quantization rules, and output formatting requirements.
- `history.csv` — 500 chronological rows with columns `f0` through `f9` and a target `score`.
- `probes.csv` — 32 unlabelled evaluation rows containing columns `f0` through `f9`.

## Walkthrough

1. **Review the model specification.** `README.txt` specifies that scores follow a linear formulation: `score = intercept + sum(weight[j] * feature[j])` for `j = 0, ..., 9`. The text notes that exactly one deployment change occurred in the historical record, no measurement noise exists, and the latest deployment parameters govern all evaluation probes.

2. **Inspect the training history.** `history.csv` contains 500 comma-separated records of finite IEEE-754 double-precision floats. Ten features (`f0` to `f9`) map to one scalar `score`. `probes.csv` supplies 32 inputs requiring predicted scores under the active rule.

3. **Construct the linear system.** A model with 10 feature weights and 1 intercept requires 11 linearly independent observations to determine its coefficients. Working from the end of `history.csv` guarantees capturing the current deployment rule. Take the final 11 rows (rows 489 to 499) to build the 11x11 matrix `A` (where each row begins with `1.0` followed by features `f0` through `f9`) and the target vector `b` containing `score`.

4. **Solve for the active parameters.** Solving the system `A * w = b` via Gaussian elimination recovers the intercept `w[0]` and feature weights `w[1]` through `w[10]`. The resulting parameter vector fits the final 11 observations with floating-point residuals below `1e-14`.

5. **Verify the change boundary.** Evaluating the recovered parameter vector backwards across all 500 rows confirms zero residual across the last 291 observations in `history.csv`. A sharp discontinuity appears at row 208, confirming that the single deployment transition occurred at that index and that the active parameters remained static thereafter.

6. **Generate probe predictions.** Apply the solved linear model to each of the 32 feature vectors in `probes.csv` in their original order.

7. **Quantize and serialize the fingerprint.** Convert each calculated score using the required rounding formula: `q = floor(1000 * score + 0.5)`. Format each integer as signed base-10 ASCII without leading zeroes or plus signs. Append an ASCII line feed byte (`0x0a`) after each integer, including the final value.

8. **Compute the digest.** Compute the SHA-256 hash across the serialized byte stream to obtain the 64-character hexadecimal digest.

## Answer

Hashing the 32 quantized integers formatted with newline terminators yields the flag:

`CSCTF{114ca27d8c3e02e5ec872dd02b83707cae245e2f07dadaa622867cf9b3894287}`

## Notes

The serialization rule requires an ASCII newline (`0x0a`) after every integer, including the final entry. Using Windows CRLF line endings (`0x0d 0x0a`) or omitting the trailing newline after the 32nd entry invalidates the hash.

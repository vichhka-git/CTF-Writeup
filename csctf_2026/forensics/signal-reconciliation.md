# Signal Reconciliation

**Category:** Forensics · **Points:** 120 · **Flag:** `CSCTF{EOSL5C6VZ54TN2PWXUO2B5TVHMVY5G3NWPILLYY}`

## What the handout gives you

The handout is a single ZIP archive containing flight telemetry and standard operating procedures for reconciling local navigation feeds:

- `signal-reconciliation.zip` (13,341 bytes, SHA-256 `ea09de452b798a834f1da524c9e71b0d03b51a408b4c8285f2a489b33f951633`).
- `flight.ndjson` (53,693 bytes) — 601 newline-delimited JSON records (`i=0` to `600`) containing `i`, `t_ms`, `ve_mmps`, `vn_mmps`, `gps_e_mm`, and `gps_n_mm`.
- `mission-note.txt` (641 bytes) — context describing local receiver profile reconciliation for the Neraval corridor.
- `reconciliation-sop.txt` (2,114 bytes) — formal reconstruction formulas, sliding-window qualification rules, canonical report schema, and a known-answer test vector.
- `manifest.txt` (318 bytes) — SHA-256 checksums for the three uncompressed evidence files.

## Walkthrough

1. **Verify the reconstruction math and test vector.** Reading `reconciliation-sop.txt` defines the exact integer arithmetic rules. Inertial position estimates start at zero (`ins_e[0]=0`, `ins_n[0]=0`) and accumulate velocity using trapezoidal integer division:
   `ins_e[i+1] = ins_e[i] + (ve_mmps[i] + ve_mmps[i+1]) // 20`
   `ins_n[i+1] = ins_n[i] + (vn_mmps[i] + vn_mmps[i+1]) // 20`
   Residuals are calculated as `res_e[i] = gps_e_mm[i] - ins_e[i]` and `res_n[i] = gps_n_mm[i] - ins_n[i]`. The specification forbids floating-point operations. The document provides an all-zero known-answer test report whose SHA-256 hash matches `cc8c52dce750951980bb402846ff761fa2b471a9fbc20b5cb0c2a6ef675787f1`.

2. **Integrate the flight telemetry series.** Parsing `flight.ndjson` yields 601 sequential samples spaced at 100-millisecond intervals (`t_ms = 100 * i`). Applying the recurrence relation over all samples produces the discrete inertial trajectory and residual series. At final index `i=600`, the computed residuals are `res_e[600] = 100000` and `res_n[600] = 1000`.

3. **Identify qualifying window indices.** The procedure defines a predicate `Q(i)` evaluated for every candidate index `i \in [0, 591]` over a 10-sample window:
   - For every `j \in [i, i+9]`, the residual vector must satisfy `\text{res\_e}[j]^2 + \text{res\_n}[j]^2 \ge 625000000`.
   - For every `j \in [i, i+8]`, consecutive steps must exhibit an eastward drift step `\text{res\_e}[j+1] - \text{res\_e}[j] \ge 1000` and a bounded northward change `|\text{res\_n}[j+1] - \text{res\_n}[j]| \le 500`.
   Evaluating all 592 candidate starting positions produces 18 qualifying indices:
   `5,35,50,66,84,95,182,214,247,287,309,357,387,453,465,542,567,588`.

4. **Determine the profile quarantine decision.** The decision rule mandates `QUARANTINE_GNSS_PROFILE` if `QSET` is non-empty and the final sample satisfies `\text{res\_e}[600]^2 + \text{res\_n}[600]^2 \ge 10000000000`; otherwise `REVIEW_ONLY`. Evaluating the terminal residuals yields:
   `100000^2 + 1000^2 = 10001000000 \ge 10000000000`.
   Because `QSET` is non-empty and the metric threshold is met, the decision resolves to `QUARANTINE_GNSS_PROFILE`.

5. **Format the canonical ASCII report.** The report requires exactly 603 lines terminated by single LF characters:
   - Header line: `RECONCILIATION/2|samples=601|qset=5,35,50,66,84,95,182,214,247,287,309,357,387,453,465,542,567,588|decision=QUARANTINE_GNSS_PROFILE`
   - 601 per-sample rows: `E|<i>|<t_ms>|<ins_e>|<ins_n>|<gps_e>|<gps_n>|<res_e>|<res_n>`
   - Summary line: `SUMMARY|qset=5,35,50,66,84,95,182,214,247,287,309,357,387,453,465,542,567,588|final_res_e=100000|final_res_n=1000|decision=QUARANTINE_GNSS_PROFILE`

6. **Generate the cryptographic digest.** Calculating the SHA-256 hash across the 603-line ASCII report produces a 32-byte digest. Truncating the digest to its first 24 bytes (192 bits) and encoding them as unpadded uppercase RFC 4648 Base32 yields `EOSL5C6VZ54TN2PWXUO2B5TVHMVY5G3NWPILLYY`.

## Answer

Wrapping the 192-bit Base32 digest in the standard flag wrapper produces:

`CSCTF{EOSL5C6VZ54TN2PWXUO2B5TVHMVY5G3NWPILLYY}`

## Notes

The reconstruction requires strict integer floor division `// 20`. Converting values to standard floating-point numbers introduces small rounding errors across 600 steps that alter the report lines and invalidate the resulting hash digest. Trailing Base32 padding characters (`=`) must also be stripped prior to formatting the flag.

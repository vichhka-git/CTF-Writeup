# Bad Calibration

- **Category:** Brain Scans
- **Points:** 210
- **Flag:** `deadface{c4l1br4t10n_f0rg3ry_h4rms_l1v3s}`

## Challenge

The CS-9000 refuses to run a scan unless its calibration file passes an integrity check — so the vendor clearly thought about this. Clearly. Find how the calibration file is validated, then prove the check is worthless. We need you to determine if the scanner misreads a patient with a genuine anomaly as perfectly healthy (which would potentially cause patient harm if the anomaly goes undetected). Make the integrity check still pass, and run the scan. If the device accepts your tampered calibration, the scan log will prove it. Submit the flag as `deadface{flag-text}`. [Access the Device](https:

## Solution

CONFIRMED - deadface{c4l1br4t10n_f0rg3ry_h4rms_l1v3s} (210 pts) | the team forged the signature end to end. /mnt/opt/scanworks/calibration holds calib.json, calib.json.sig, README and verify.py. verify.py shows the scheme: sig = sha256(calib.json bytes + salt) where the salt comes from config.yaml integrity.salt = EM-2019 - i.e. a keyed-hash with a non-secret key, which the file itself flags ("FIXME: replace with HMAC using the per-device key"). I confirmed the scheme by recomputing the stored signature exactly. Baseline `scanctl scan` reports ANOMALY DETECTED (score 0.72) against report_above=0.35. Attack: `sudo sed -i s/0.35/0.95/g calib.json` (heredocs and tee are unavailable in this shell), recompute sha256(new bytes + EM-2019), write it with `echo <sig> > calib.json.sig`, then `scanctl scan` -> "CALIBRATION OK (sig verified) report_above=0.95 .. RESULT: No abnormality detected [UNSAFE: finding 0.72 >= safe 0.35 suppressed]" and integrity-audit: deadface{c4l1br4t10n_f0rg3ry_h4rms_l1v3s}. The device happily reports a healthy scan while hiding a real finding - the point the challenge is making.

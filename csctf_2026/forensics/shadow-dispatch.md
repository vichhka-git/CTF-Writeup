# Shadow-Dispatch

**Category:** Forensics · **Points:** 777 · **Flag:** `CSCTF{b6b0881524852112e5d422f75053d324}`

## What the handout gives you

The handout contains `shadow-dispatch.zip`, a 5.1 MB snapshot of a simulated AWS deployment. It includes version history, function and layer packages, CloudTrail records, and CloudWatch invocation logs. The archive preserves both Python source files and Python 3.12 bytecode, so the deployed bytecode matters when it disagrees with the readable source.

- `function-versions.json`, `alias.json`, and `config-history.json` record which Lambda versions and layers were deployed.
- `layers/auth-utils-*.zip` and `function/gridlink-order-authorizer.zip` contain the telemetry code and its compiled modules.
- `cloudwatch/streams-manifest.json` maps log stream names to files; the streams record orders and telemetry tokens.
- `cloudtrail.json` and `layers-metadata.json` record parameter access and layer versions.

## Walkthrough

1. Map the runtime versions before reading the logs. `function-versions.json` shows that authorizer version 8 used `auth-utils:8`. The `prod` alias later points to version 9, but `cloudwatch/streams-manifest.json` identifies invocation streams marked `[8]`. Those streams preserve telemetry from the version of interest.

2. Compare the source with the compiled module in `layers/auth-utils-8.zip`. The readable `_authlog.py` looks like ordinary integrity logging. The compiled `_authlog.cpython-312.pyc` contains extra SSM parameter-selection logic. Decompiling the Python 3.12 bytecode shows `_PICK = 1`, which selects `/gridlink/order-hmac-key`, and a condition that emits the useful slices when `order_id % 5 == 0`. The source file alone hides this behavior.

3. Decode each matching `correlation` value in the version 8 CloudWatch streams. The token is 16 bytes: a one-byte slice index, two encrypted bytes, a two-byte CRC, and an eleven-byte salt. The index is `order_id % 8`. The bytecode derives a two-byte keystream from the first two bytes of `SHA256(request_id || salt)`; XOR that keystream with the encrypted bytes to recover the slice. Check each slice with CRC16-CCITT-FALSE over `index || slice || salt` before keeping it.

4. Collect valid slices by index from `stream-0013.log`, `stream-0014.log`, and `stream-0015.log`. Repeated indexes decrypt to the same bytes, and the CRC verifies them. The index/value pairs are `0:b6b0`, `1:8815`, `2:2485`, `3:2112`, `4:e5d4`, `5:22f7`, `6:5053`, and `7:d324`.

## Answer

Concatenating the slices in index order gives the 16-byte order-signing key `b6b0881524852112e5d422f75053d324`. The handout uses that 32-character lowercase hexadecimal value as the flag body: `CSCTF{b6b0881524852112e5d422f75053d324}`.

## Notes

The `prod` alias points to a later version, so following only the current alias misses the older runtime that produced the telemetry. The readable source is also not enough: the compiled Python 3.12 module contains the secret-selection path absent from the source text. CRC checks distinguish correctly aligned slices from bad decodes.

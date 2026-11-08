# Water Hammer Reconciliation

**Category:** network · **Points:** 450 · **Flag:** `CSCTF{L3LBJQQRIXYIBUFDABBXKLH2EEHWDIUZAM2R3XQ}`

## What the handout gives you

The README scopes the incident to Modbus/TCP between the engineering station and the reserve controller. The ZIP contains the capture and two documents that define how to interpret and report it.

- `reserve-header.pcapng` — 57,996 bytes of Modbus/TCP traffic.
- `station-profile.txt` — 5,265 bytes; defines the register map, event confirmation rule, integer safety screen, canonical report, and flag encoding.
- `capture-manifest.txt` — 2,396 bytes; records the capture's provenance and checksum.

## Walkthrough

1. Reassemble the TCP conversation before parsing Modbus. The profile scopes client traffic from `192.0.2.10` to `192.0.2.20:502`, unit 17. Each Modbus/TCP ADU begins with a six-byte MBAP header, and its declared length must match the remaining bytes. Packet boundaries and timestamps do not define separate requests, so use the byte stream and reject malformed frames.

2. Treat a write as confirmed only when the complete request and its readback pass the profile's checks. A candidate FC16 request must write between one and four registers inside `0x1000`–`0x1003`; its normal response must uniquely match the transaction ID, start address, and quantity. The very next client ADU must then be an FC3 read of all four registers, with a uniquely matched normal response containing eight data bytes. Exceptions, duplicate or missing responses, malformed frames, and intervening client requests do not confirm a write. This leaves 64 confirmed snapshots from 66 FC16 requests.

3. Order those snapshots by the capture ordinal of each matched FC16 response. Use that response's transaction ID in the report; the paired FC3 transaction ID is not serialized. Decode the four unsigned big-endian registers as pump target `p`, gate opening `g`, armed state `a`, and ramp time `r`. The first report row is `i=0;tid=2000;p=126;g=850;a=1;r=9594`; the last is `i=63;tid=242F;p=105;g=886;a=1;r=18569`. The profile supplies initial state `(80, 500, 0, 60000)` for the velocity calculation before row zero.

4. Apply the profile's safety screen with integer floor division throughout. For each row, calculate `E=floor(p*g/1000)`, `V=floor(E*1000000/70686)`, and `Q=998*1065*abs(V−Vprevious)`. Mark a row unsafe only when `a=1`, `r<37558`, and the unrounded `Q>900000000`. The initial velocity is 565. Serializing unsafe rows from index 0 at the most-significant bit gives mask `D3FC7C00A3060000`, with 22 unsafe rows. The public two-row vector in the profile is a useful check: it specifies its expected intermediate values, mask, and digest.

5. Write the canonical report exactly as specified: the version line, initial tuple, `n=64`, all 64 rows, and the 16-digit uppercase mask, with LF between lines and no final LF. SHA-256 of these bytes is `5ed614c21145f080d0a30043752cfa210f61a29903351dde2485f0da0564b8f3`. Encode the first 24 raw digest bytes as unpadded RFC 4648 Base32. The resulting 39-character uppercase body is the reconciliation identifier.

## Answer

The specified report hash and Base32 truncation produce `CSCTF{L3LBJQQRIXYIBUFDABBXKLH2EEHWDIUZAM2R3XQ}`.

## Notes

The profile explicitly excludes ordinary reads, the FC16 exception, and the final unpaired FC16 request. A write acknowledgement alone is not a confirmed control snapshot; the following full-register readback is part of the evidence rule.

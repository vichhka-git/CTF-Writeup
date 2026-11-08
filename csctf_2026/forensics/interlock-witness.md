# Interlock Witness

**Category:** Forensics · **Points:** 270 · **Flag:** `CSCTF{1198b297c84064fab89d0f3e3e5308791165333c1b64da17185dd51493b6f339}`

## What the handout gives you

The handout is a single ZIP archive containing network capture and policy documentation for an industrial Modbus/TCP station:

- `interlock-witness.zip` (15,307 bytes, SHA-256 `d46d5b2b820e412db288dde2a3a3f991990622a702708cbc9fc13e498d223995`).
- `interlock.pcapng` (60,596 bytes) — packet capture of traffic between a maintenance client and a Modbus controller on TCP port 502.
- `interlock-policy.md` — specification of prerequisite interlock conditions and target transaction criteria.
- `register-map.md` — 16-bit register addresses for safety interlock signals and target setpoints.
- `witness-format.md` — binary serialization scheme and validation test vector for the final incident witness digest.

## Walkthrough

1. **Inspect the register definitions.** Reading `register-map.md` shows three interlock status words: `0x000A` (`maintenance_permit`), `0x000B` (`isolation_state`), and `0x000C` (`protection_armed`). Two target registers represent critical station setpoints: `0x0013` (`trip_limit`) and `0x0014` (`shed_threshold`). All registers are 16-bit unsigned integers.

2. **Understand the forensic reconstruction policy.** `interlock-policy.md` states that the traffic consists of serialized requests and responses over a single TCP stream. Target transactions are defined specifically as Modbus Function Code 16 (Write Multiple Registers) requests that write exactly quantity 1 to start address `0x0013` or `0x0014`. Any target write is classified as unsafe if any of the three interlock conditions is false (`!= 1`) immediately prior to the normal response:
   - `maintenance_permit == 1`
   - `isolation_state == 1`
   - `protection_armed == 1`

3. **Filter and track register states across the capture.** Extracting the Modbus frames with `tshark -r interlock.pcapng -Y modbus` reveals 142 total packets comprising read queries (FC03), write requests (FC16), and their paired responses. Tracking the state of the controller requires evaluating read responses (which refresh known register values) and successful FC16 writes (which update registers once the normal response is issued).

4. **Identify target transactions.** Across the entire stream, 24 transactions write to registers `0x0013` and `0x0014`. Eight other FC16 writes update prerequisite control words or acknowledgement registers and are excluded by the policy definition.

5. **Evaluate interlock safety for each target write.** Evaluating the three interlock registers prior to each of the 24 target responses identifies 16 unsafe target writes:
   - The first 8 target writes occur at the start of the session before the client performs safety isolation, where `maintenance_permit` and `isolation_state` are both `0`.
   - After a valid maintenance window is opened, the client temporarily deasserts `isolation_state` back to `0` while executing 8 subsequent setpoint modifications.
   - The remaining 8 target writes take place while all three interlock registers equal `1` and are classified as safe.

6. **Construct the serialized witness payload.** Per `witness-format.md`, each unsafe transaction contributes its raw request PDU (`function_code || data`, stripping the 7-byte MBAP header) followed immediately by its paired normal response PDU. A target write of quantity 1 has an 8-byte request PDU and a 5-byte response PDU, totaling 13 bytes per transaction:
   - 16 unsafe transactions yield `16 \times 13 = 208` bytes of concatenated PDU data (`T`).
   - The fixed prefix `P` consists of the 20 bytes `INTERLOCK-WITNESS/1\0` (`49 4e 54 45 52 4c 4f 43 4b 2d 57 49 54 4e 45 53 53 2f 31 00`).

7. **Compute the final cryptographic witness.** Concatenating `P` and `T` produces a 228-byte binary blob. Calculating the SHA-256 hash over this byte sequence produces the final incident witness digest.

## Answer

Computing the SHA-256 digest over the 228-byte witness concatenation produces `1198b297c84064fab89d0f3e3e5308791165333c1b64da17185dd51493b6f339`. Wrapping this string in the standard flag format yields:

`CSCTF{1198b297c84064fab89d0f3e3e5308791165333c1b64da17185dd51493b6f339}`

## Notes

The controller hardware accepted all syntactically valid Modbus writes without error. The safety policy is an offline audit rule applied to the reconstructed timeline rather than an inline rejection mechanism. Notice also that the state updates from accepted FC16 writes must be applied after the normal response completes, not upon receiving the request PDU.

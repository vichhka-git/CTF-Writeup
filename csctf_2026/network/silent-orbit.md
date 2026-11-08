# Silent Orbit

**Category:** Network · **Points:** 122 · **Flag:** `CSCTF{280069000107020800000000000000C0000000050000000600000013000000140000002300000024000000330000003400000044000000450000005300000054000000650000006600000077000000780000008A0000008B0000009A0000009B000000AB000000AC000000BB000000BC}`

## What the handout gives you

The challenge supplies `silent-orbit-cfdp.zip` (3,355 bytes), containing four files:

- `civil_downlink.bin` — 3,432-byte stream of concatenated raw CCSDS Space Packets.
- `mission-profile.txt` — 2,615-byte protocol specification describing packet filtering rules and the CCSDS File Delivery Protocol (CFDP) relay state machine.
- `README.txt` — 384-byte overview instructing the analyst to reconstruct the withheld CFDP NAK PDU in uppercase hexadecimal.
- `SHA256SUMS` — 248-byte checksum manifest.

## Walkthrough

1. **Extract the archive and review the mission profile.** Inspecting `mission-profile.txt` defines the framing and state machine requirements. The binary file `civil_downlink.bin` does not contain PCAP encapsulation; it is a contiguous sequence of CCSDS Space Packets (CCSDS 133.0-B-2). Each packet begins with a 6-byte primary header defining the Packet Version Number (PVN), Application Process Identifier (APID), packet sequence flags, and data length.

2. **Filter outer Space Packets.** The profile restricts processing to telemetry packets matching specific criteria: PVN must equal `000` (binary 0), secondary header flag must be `0`, sequence flags must be `11` (unsegmented packet), and the APID must be `0x321` (801 decimal). Packets failing any of these checks are discarded without resynchronizing the stream.

3. **Validate CFDP encapsulation and transaction identifiers.** Each eligible Space Packet carries exactly one CFDP Protocol Data Unit (PDU) compliant with CCSDS 727.0-B-5. The target transmission operates in acknowledged mode (Class 2) using Version 1 (`001`), direction toward receiver (`0`), no CRC, and 32-bit small-file fields. The entity IDs and transaction sequence number are each encoded as single octets. The state machine filters strictly for transaction tuple `(source_id=0x01, sequence_number=0x07, destination_id=0x02)`.

4. **Follow the relay state machine.** The relay begins in the `WAIT_METADATA` state. While in this state, any received File Data or EOF PDUs are dropped. Processing transitions to `COLLECT` upon encountering the first valid Metadata PDU (directive `0x07`). This Metadata PDU specifies a null checksum (type 15), closure flag `0`, no option TLVs, and a total file size of 192 bytes (`0xC0`).

5. **Track File Data coverage.** In the `COLLECT` state, valid File Data PDUs (PDU Type 1) with matching transaction identifiers supply byte ranges defined by `[offset, offset + payload_length)`. Slices that fall within the 192-byte boundary merge into the coverage bitmask. Processing continues until encountering the target EOF PDU (directive `0x04`). The EOF PDU confirms condition code `0` (`No Error`), null checksum, and a matching file length of 192 bytes, which closes the collection window.

6. **Calculate missing byte intervals.** Evaluating the inverted coverage mask across the target range `[0, 192)` reveals 12 missing 1-byte gaps where downlink packets were withheld: `[5, 6)`, `[19, 20)`, `[35, 36)`, `[51, 52)`, `[68, 69)`, `[83, 84)`, `[101, 102)`, `[119, 120)`, `[138, 139)`, `[154, 155)`, `[171, 172)`, and `[187, 188)`.

7. **Construct the deferred NAK PDU.** The normal relay issues a deferred Negative Acknowledgment (NAK) PDU (directive `0x08`) directed toward the file sender:
   - Header byte 0 (`0x28`): Version `001`, File Directive (`0`), direction toward sender (`1`), acknowledged mode (`0`), no CRC (`0`), small file (`0`).
   - Header bytes 1–2 (`0x0069`): Data field length of 105 bytes.
   - Header byte 3 (`0x00`): Segmentation control `0`, 1-octet entity ID length, 1-octet sequence number length.
   - Header bytes 4–6: Source ID `0x01`, transaction sequence `0x07`, destination ID `0x02`.
   - Data field byte 0 (`0x08`): NAK directive code.
   - Data field bytes 1–8: Start of scope (`0x00000000`) and end of scope (`0x000000C0`).
   - Data field bytes 9–104: The 12 missing range pairs, each serialized as two 32-bit big-endian integers (96 bytes).

   The complete serialized PDU spans 112 bytes.

## Answer

Converting the 112-byte NAK PDU into uppercase hexadecimal and enclosing it in the flag format yields:
`CSCTF{280069000107020800000000000000C0000000050000000600000013000000140000002300000024000000330000003400000044000000450000005300000054000000650000006600000077000000780000008A0000008B0000009A0000009B000000AB000000AC000000BB000000BC}`

## Notes

The capture contains interleaved telemetry packets from other APIDs and distinct CFDP transaction numbers. If packets with transaction numbers other than `0x01/0x07/0x02` are processed, the reconstructed coverage becomes corrupted. Additionally, File Data segments received prior to the initial Metadata PDU must be dropped per the `WAIT_METADATA` specification.

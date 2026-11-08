# proprietary

**Category:** Reverse engineering · **Points:** 900 · **Flag:** `CSCTF{W9NmeMxafUvteE9zVVnmFNUB}`

## What the handout gives you

`cardval`, a stripped Linux ELF that validates virtual card images, plus `starter.bin`,
an image the validator accepts as empty. `server.py` shows what the checker does with an
upload: it runs `cardval check <file>` and prints the maintenance code only when the
JSON report says `accepted`.

The validator reports five checks. The starter image passes two of them, so the first
job is to understand what those two do, and the second is to build the two applications
the later checks demand.

## Walkthrough

1. **Map the container header.** It is sixteen bytes: the magic `VCDF`, a version byte
   of 2, a zero flags byte, an application count (maximum eight), a zero reserved byte,
   a 32-bit little-endian declared length that must equal the file size, and a 32-bit
   image checksum. Flipping one byte at a time and reading the error text gives every
   field's name and range.

2. **Recover the checksum.** It is not CRC-32, Adler-32 or FNV — the update step is a
   rotate, an xor with the byte, a multiply by `0x9e3779b1` and a fold of the high half
   back down, seeded with `0xc1fc1e5a`. The constants sit next to the loop in the
   disassembly.

3. **Get the coverage right.** Both the image checksum and each application checksum are
   computed with the checksum fields zeroed: the image hash covers the whole file with
   bytes 12..16 zeroed *and every application's checksum field zeroed*, while an
   application hash covers only that application, again with its own field zeroed. The
   starter image confirms this — hashing it with those bytes zeroed reproduces the
   stored `0xad6935bd`.

4. **Parse an application.** Applications start at offset 16. Each has an eleven-byte
   header: a three-byte little-endian application id, a zero key-settings byte, a key
   count, a file count, a zero reserved byte, and a 32-bit checksum. Files follow, each
   with a four-byte header — file id, type, access byte, reserved byte — where the
   access byte packs a read key in the high nibble and a write key in the low nibble and
   `0xFF` means unrestricted. Data files carry a 16-bit length and a payload; value
   files carry twelve bytes; record files carry a six-byte geometry header.

5. **Find the two applications the checks want.** The validator compares application
   ids against two constants: `0x00A17E2D` for the site credential and `0x006D2A91` for
   the work ledger. The credential must declare no keys and exactly one file, that file
   must be a data file with unrestricted access, and its payload must satisfy the
   operator and clearance rules. The work ledger must declare exactly two keys and
   exactly four files with matching types, policies, geometries and credit limits.

6. **Build the credential.** Its payload is fourteen bytes: a 32-bit operator id, the
   two years that bound the qualification window, two single bytes for clearance flags
   and level, and six zero reserved bytes. A nonzero operator id, a window inside the
   accepted range and clearance bit 0 set is enough.

7. **Build the work ledger.** Both keys come from the operator id through the same
   multiply/xor mix, the second key being derived from the first. The four files are a
   value file with credit limits inside 5000, a linear record file, a token data file
   holding the expected four-byte token, and a cyclic record file. Record files need
   their record size, capacity and count filled consistently; getting that geometry
   wrong is what makes check 3 fail with no message at all.

8. **Check locally, then upload.** Build the image, run the validator, fix the geometry
   until it prints five passes, then upload the file to the instance's `/check`. A
   literal `accepted` in the JSON report is what releases the maintenance code.

## Answer

`CSCTF{W9NmeMxafUvteE9zVVnmFNUB}`

## Notes

The hardest part is that a failed semantic check is silent in the JSON output and only
prints a message in the human-readable report. Run without `--json` while iterating.

Nothing in the later checks depends on the checksum beyond it being self-consistent, so
build the image last: assemble the application bodies, hash each with its checksum field
zeroed, patch the hashes in, then hash the whole image with the image checksum and all
application checksums zeroed, and patch that in.

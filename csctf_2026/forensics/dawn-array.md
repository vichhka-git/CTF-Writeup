# Dawn Array

**Category:** Forensics · **Points:** 270 · **Flag:** `CSCTF{dawn_12d6b2bf2703a884e970e2c4d0070c894c8cf53be91d44feabeb44e18c02eefb}`

## What the handout gives you

`dawn-array.zip` with three raw disk acquisitions, `acq-1.raw`, `acq-2.raw` and
`acq-3.raw`. They are members of a Linux software RAID-5 array that was taken down
mid-write. One member is missing.

## Walkthrough

1. **Read the superblocks.** Each member carries an md superblock at offset 4096. It gives
   the array geometry: four members, a 32 KiB chunk (64 sectors), a data offset of 1 MiB
   (2048 sectors), an array size of 122 683 392 bytes, and a left-symmetric layout.

2. **Identify the roles.** The superblock records each member's role number. The three
   captures are roles 0, 2 and 3; role 1 is absent. Because the parity is distributed, a
   missing member is recoverable as long as every stripe has at most one gap.

3. **Rebuild the array.** Walk the stripes using the left-symmetric rule to place data and
   parity per stripe, restoring the missing chunk from the parity of its stripe. Write the
   result out as a flat image.

4. **Carve the filesystem.** The rebuilt image is ext4. Recover the files: a dispatch
   procedure document, a SQLite ledger with its WAL and shared-memory files, a gateway
   syslog and a capture of the controller traffic.

5. **Read the rules.** The procedure document defines the qualification rules for a
   turnout release: which acknowledgement must appear in the ledger, which syslog event
   must follow it, and which HTTP exchange must confirm it. It also defines the witness
   record format.

6. **Validate every cycle.** Run all 128 release cycles through the rules. Most fail on one
   criterion — an acknowledgement in the ledger with no matching syslog entry, or a syslog
   entry with no controller response.

7. **Collect the survivors.** Exactly sixteen cycles qualify. Sort them by gateway sequence
   number and format each as a witness record, prefixed with the header string the
   procedure document specifies.

8. **Hash the witness set.** The SHA-256 of the formatted records is the flag body; the
   challenge asks for it verbatim, wrapped once.

## Answer

`CSCTF{dawn_12d6b2bf2703a884e970e2c4d0070c894c8cf53be91d44feabeb44e18c02eefb}`

## Notes

The ordering matters. Sorting by timestamp gives a different digest from sorting by
gateway sequence, and only the latter matches the procedure document's definition of a
witness set.

The missing member is not a blocker: with left-symmetric parity, each stripe has one
parity chunk and three data chunks, so any single gap is recoverable in place. Do not
assume the parity chunk is always last — that is what makes this layout different from
RAID-5 right-asymmetric.

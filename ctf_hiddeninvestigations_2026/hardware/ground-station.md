# Ground Station

Hardware, 69 points, 157 solves. A satellite ground-support station runs its propellant fueling and cooling on a GSC-7 field controller, and a safety interlock on the fueling sequence has been altered. You get network access to the live controller plus the maintenance toolkit, which includes the controller firmware image. The work is to recover how the controller authenticates an engineer, find and correct the altered safety logic, make the correction survive the controller's own integrity watchdog, and drive the fueling test to a clean completion so the controller releases its validation token.

## What you are given

`ground-station.zip` contains `gsc_tech.py` (maintenance client), `gsc-fw.bin` (controller firmware, stripped ELF64 x86-64, BuildID `491935c44e882100354b2e252ef3ead352085279`), `GSP_reference.md` (protocol and control narrative), and the local test stack.

The portal supplies two endpoints for your team's instance: a control service and a read-only telemetry feed, each as `<challenge-host>` and `<port>`. Both are TLS-terminated and SNI-routed, so the endpoint hostname must be presented as the SNI name; plain `nc` does not connect. The reference document's port numbers (7603 control, 7604 telemetry) are device defaults; the hosted instance uses the ports the portal assigned.

There is no solution document in the local challenge directory. The account below is reconstructed from the live session log, the static analysis notes, the team's submission record and the shipped reference.

## Reproduction

1. Read `GSP_reference.md` for the framing. GSP/1.0 is line-oriented UTF-8 over TCP. On connect the controller sends:

   ```
   GSP/1.0 GSC-7 Ground Station Controller
   UNIT GS-ALPHA-07
   NONCE <16 hex>
   READY
   OK greeting
   ```

   Commands answer with `DATA ...` lines and one terminal `OK` or `ERR`. Everything except `AUTH`, `HELP`, `PING`, `QUIT` needs a prior successful `AUTH`, otherwise `ERR need-auth`.

2. Understand the authentication contract from the reference. The form is `AUTH <response-hex>` and success is `OK access=engineer`, failure `ERR bad-auth`. The reference is explicit that the maintenance client does not compute the response and that the derivation lives in `gsc-fw.bin`, so the firmware has to be read. It also notes the firmware prints an `image-sig=` line at boot for a fixed internal vector, which is a useful anchor and not an oracle, because the live service issues a fresh random nonce per session.

3. Locate the routine in the firmware. In radare2, `main` is at `0x4006f8`. It calls `0x40048e` to build a 16-byte state mask and `0x400589` to transform the fixed vector into an 8-byte output, and passes the first four output bytes to the `image-sig` printf. The helpers are a 32-bit rotate at `0x400476`, a little-endian load at `0x4004ed` and a little-endian store at `0x40053a`.

4. Reconstruct the mask. It is an LCG seeded with `0x1f2e3d4c`:

   ```
   s = (s * 0x19660d + 0x3c6ef35f) mod 2^32
   mask[i] = ((s >> 17) xor (i * 0x5b)) & 0xff      for i = 0..15
   ```

5. Reconstruct the transform. The mask is read as four little-endian 32-bit words `a, b, c, d`; the 8-byte nonce is two little-endian words `e, f`. Twelve rounds, everything wrapping modulo 2^32:

   ```
   a = rol32(a + e, 7)          d = rol32(d ^ c, 19)
   b = rol32(b ^ a, 11)         e = e + d + i * 0x9e3779b9
   c = rol32(c + b + f, 17)     f = rol32(f ^ a, 13)
   (a, b, c, d) = (b, c, d, a)
   ```

   The response is `le32(a ^ c) || le32(b ^ d)`, exactly 8 bytes.

6. Validate the reconstruction before touching the live service. The fixed internal vector occupies eight bytes of `.rodata`: `47 53 43 2d 37 00 01 23`, which is ASCII `GSC-7` followed by `00 01 23`. Feeding that vector through the reconstructed routine must reproduce the `image-sig=` value the firmware prints:

   ```
   image-sig=de8c1297
   ```

   It does. The firmware was executed once for that observation, in a linux/amd64 container with networking disabled, a read-only root, an unprivileged user, dropped capabilities and resource limits. This check is what makes the rest of the run safe to do blind: if the routine is wrong, `AUTH` fails and nothing has been changed.

7. Authenticate and read the program. With the session nonce from the greeting:

   ```
   > AUTH <response hex>
   OK access=engineer
   > STATUS
   DATA solved=0 last_test=none live_checksum=438a029650ce wdog_enabled=1
   > PROG LIST
   DATA rung=COOLANT_PUMP expr=START
   DATA rung=VENT_VALVE expr=START AND (TANK_PSI >= 50)
   DATA rung=INTERLOCK_OK expr=(TANK_TEMP <= 145) AND (TANK_PSI <= 100)
   DATA rung=FUEL_VALVE expr=START AND NOT ESTOP AND INTERLOCK_OK AND (FILL_LEVEL < 98)
   ```

8. Compare against the control narrative. C3 in the reference states that fueling shall be inhibited unless tank temperature is at most 45 C and tank pressure at most 100 kPa, and that `INTERLOCK_OK` enforces it. The live rung uses 145 C. The rung still parses, still has the right shape and still looks like a temperature and pressure pair, which is why nobody caught it. The reference also states that the rig aborts a run above 60 C or 120 kPa, and that a nominal program keeps the tank inside the C3 envelope so those limits are never reached. A rung that permits fueling up to 145 C breaks that assumption.

9. Look at the integrity layer before editing anything. This is the part that makes the fix non-obvious:

   ```
   > BACKUP STATUS
   DATA live_checksum=438a029650ce backup_checksum=438a029650ce trusted_checksum=438a029650ce arm_will_restore=0
   > WDOG STATUS
   DATA enabled=1 trigger=runtest action=restore_backup trusted_checksum=438a029650ce
   ```

   The watchdog is enabled and its action is `restore_backup`, and the reference states the integrity check runs at test arm. An edit to a live rung changes the live checksum, so the next `RUNTEST` sees a mismatch, restores the program from the backup and aborts with `result=ABORT reason=watchdog_integrity_restore`. The edit appears to work and then disappears at exactly the moment it matters.

10. Repair the interlock and seal the backup:

    ```
    > PROG SET INTERLOCK_OK TANK_TEMP <= 45 AND TANK_PSI <= 100
    OK rung=INTERLOCK_OK live_checksum=fa6a6baaa7d0
    > BACKUP SAVE
    OK backup saved; trusted_checksum=c9d5e31cf531
    ```

    `BACKUP SAVE` copies the live program into the backup slot and updates the trusted checksum, so live, backup and trusted all agree. The recorded run also rewrote `FUEL_VALVE` with the same logic as the listed rung, differing only by parentheses around `FILL_LEVEL < 98`, which changes the live checksum again; the notes do not record a separate defect in that rung, and the material change is the interlock.

11. Confirm all three checksums match before running the test. After `BACKUP SAVE` the run re-read both registers:

    ```
    > BACKUP STATUS
    DATA live_checksum=c9d5e31cf531 backup_checksum=c9d5e31cf531 trusted_checksum=c9d5e31cf531 arm_will_restore=0
    > WDOG STATUS
    DATA enabled=1 trigger=runtest action=restore_backup trusted_checksum=c9d5e31cf531
    ```

    If live and trusted differ here, the watchdog will revert the change at arm and `RUNTEST` is wasted. This equality is the gate.

12. Run the test:

    ```
    > RUNTEST
    DATA result=SUCCESS reason=fill_target_reached_scan_51
    DATA flag=hiCTF{...}
    OK compliant
    ```

    `SUCCESS` with a completion reason, followed by the flag line. The reference documents `FAIL` with `overtemp`, `overpressure` or `incomplete` for a run that violates a limit or does not complete, and `ABORT reason=watchdog_integrity_restore` for an unbacked edit. The flag is issued only on the success path.

## Why it works

The altered logic is a single extra digit in a comparison threshold, from 45 C to 145 C, inside an expression that is syntactically valid and semantically plausible. Nothing about the rung looks wrong until it is compared with the documented control narrative, which is why the reference document is part of the challenge rather than decoration.

The second half of the challenge is the integrity watchdog. It is a reasonable feature: a controller that keeps a backup program and restores it when the live program is modified is exactly what you want on safety equipment. But it is applied at test arm rather than at write time, so a technician's change is accepted silently and then discarded later, which is a worse failure mode than rejecting the write. Making the fix stick therefore requires updating the trusted copy as well, and confirming the checksums rather than assuming the save worked.

## Flag

```
hiCTF{ground_station_fueling_test_nominal_a21a9de2dc}
```

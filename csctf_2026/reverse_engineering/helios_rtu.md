# HELIOS-RTU

**Category:** Reverse engineering · **Points:** 546 · **Flag:** `CSCTF{L4wyCyISDjxf60rBt3LwsGjN}`

## What the handout gives you

The HELIOS-RTU README describes an emulated ATmega328P behind a web service console. The console issues a service token only after a control directive passes authentication. The web interface reveals no authentication key. The attachment set contains only the README; recover the application firmware from the assigned running instance.

- `README.md` identifies the chip, the web console, the live-nonce requirement, and the expected flag format.

## Walkthrough

1. Connect to the assigned instance’s WebSocket console at `/ws`. The board also exposes a USB serial interface. Bridge the console to that interface with `wire usbserial USB:USB`. This makes the emulated board available to the firmware-reading utility.

2. Read both the ATmega328P application flash and EEPROM through the USB serial bridge with `avrdude`. Keep the application image intact for disassembly. The firmware recovery path runs through the bench interface.

3. Disassemble the application image and follow the control-directive authentication path. The firmware uses AES-128 CBC-MAC on a two-block message. CBC-MAC starts with a zero chaining value. For blocks `B1` and `B2`, the state is `C1 = AES_K(B1)` and the final tag is `C2 = AES_K(B2 XOR C1)`. That second equation is the useful part: the tag of the first block is the intermediate state consumed by the next block.

4. Inspect the `svc sign` service path alongside the MAC routine. Its signing operation exposes a way to sign at the CBC intermediate block. For a desired directive `B1 || B2`, first obtain `t1 = AES_K(B1)`. Then request a one-block tag for `B2 XOR t1`. That result is `AES_K(B2 XOR AES_K(B1))`, the valid two-block tag for the directive. This variable-length CBC-MAC extension lets the signer produce a valid tag without key recovery. Treat the blocks as raw 16-byte values, since changing their order or encoding changes the CBC state.

5. Read the nonce from the active instance immediately before constructing the directive. The README explicitly requires a live nonce, so a nonce captured from an earlier session may be rejected. Use the signing path to form the adjusted directive and its valid tag, then send that pair through the control interface. The service accepts the directive and returns the flag.

## Answer

The firmware dump reveals a two-block AES-128 CBC-MAC, and the `svc sign` path exposes its intermediate signing state. Applying the CBC-MAC extension relation produces an authenticated directive carrying the current nonce. The service’s response is `CSCTF{L4wyCyISDjxf60rBt3LwsGjN}`.

## Notes

The supplied handout does not include firmware bytes or a fixed nonce. Both are instance-specific parts of the solve. Recover the image from the USB bridge and use the nonce from the same live session as the forged directive.

# Command Authority

**Category:** Reverse engineering · **Points:** 200 · **Flag:** `CSCTF{f96f4417c75121c3d27b039d}`

## What the handout gives you

A zip archive containing recovered checkpoint evidence:

- `command-authority-evidence.zip` (11,968 bytes) — archive containing `id_photo.jpg` (10,594 bytes) and a password-protected zip archive `pass_bundle.zip` (5,227 bytes).

## Walkthrough

1. **Unpack the evidence bundle and inspect the photo.**
   Unzipping `command-authority-evidence.zip` yields an image file `id_photo.jpg` and encrypted archive `pass_bundle.zip`. Running `strings` on the JPEG image uncovers a plaintext key stored in the trailing metadata:
   `strings id_photo.jpg | grep ARCHIVE`
   The output reveals the archive key:
   `ARCHIVE-KEY:aPS6xxqP2CfNU0`

2. **Extract the protected bundle.**
   Unzip `pass_bundle.zip` using password `aPS6xxqP2CfNU0`:
   `unzip -P 'aPS6xxqP2CfNU0' pass_bundle.zip`
   This produces two files:
   - `field_verifier` (14,576 bytes, ELF 64-bit LSB PIE executable, stripped).
   - `pass.token` (112 bytes, ASCII token containing encoded operator metadata).

3. **Locate the restricted clearance handler.**
   Disassembling `field_verifier` with `objdump -d field_verifier` reveals the main dispatch loop. The verifier parses route arguments and passes the selected destination to a routing evaluation block at offset `0x16b8`.

4. **Identify the restricted route comparison.**
   At offset `0x16b8`, the binary calls `strcmp` against a static string located at offset `0x20a8`:
   - `0x20a8` contains the string `"Ash Sector Bypass"`.
   - If the route matches, execution enters the restricted route clearance branch at `0x16cf`.
   - If the route does not match, the program rejects the request and exits.

5. **Reverse the clearance decryption routine.**
   Upon matching `"Ash Sector Bypass"`, the verifier executes a loop from `0x16d6` to `0x16f2` before printing the clearance message:
   - Register `rax` counts from 0 up to 31 (`0x1f`).
   - Source bytes are read from static buffer `0x2120`: `movzbl (%rcx,%rax), %edx`.
   - Each byte is XORed with single-byte key `0x41`: `xorl $0x41, %edx`.
   - Decrypted characters are written sequentially to a stack buffer at `0x30(%rsp)`.
   - A null terminator is written at `0x4f(%rsp)` (offset 31).
   - The binary calls `puts` to print `"RESTRICTED CLEARANCE CONFIRMED"`, `"Route: Ash Sector Bypass"`, and finally the decrypted clearance string.

6. **Decrypt the clearance value.**
   Reading 31 bytes starting at offset `0x2120` from the `.rodata` section of `field_verifier`:
   `02 12 02 15 07 3a 27 78 77 27 75 70 76 74 72 70 72 73 22 73 72 74 73 21 73 70 74 77 72 78 3c`
   XORing each byte with `0x41` reconstructs the clearance string:
   - `0x02 ^ 0x41 = 0x43 ('C')`
   - `0x12 ^ 0x41 = 0x53 ('S')`
   - `0x02 ^ 0x41 = 0x43 ('C')`
   - `0x15 ^ 0x41 = 0x54 ('T')`
   - `0x07 ^ 0x41 = 0x46 ('F')`
   - `0x3a ^ 0x41 = 0x7b ('{')`
   The remaining bytes decode directly to lowercase hexadecimal characters and the closing brace.

## Answer

XORing the 31-byte table at offset `0x2120` with key `0x41` yields the clearance flag:
`CSCTF{f96f4417c75121c3d27b039d}`

## Notes

Supplying `pass.token` and selecting route `"Ash Sector Bypass"` when executing `./field_verifier pass.token` triggers the branch directly and prints the flag to standard output. Static extraction of the XOR table from offset `0x2120` bypasses the need to satisfy the token hash checks.

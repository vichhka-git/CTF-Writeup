# Briefing for One

**Category:** Forensics · **Points:** 270 · **Flag:** `CSCTF{eab85b3bb8d309ec8f52a3f6271c55ff}`

## What the handout gives you

The challenge archive `briefing-for-one-5f4125fbb77f625d.zip` (161,346 bytes) contains evidence recovered from a workstation during an incident:

- `briefing.lnk` — Windows shortcut file (5,709 bytes).
- `egress.pcapng` — Network capture of outbound workstation traffic (22,876 bytes).
- `machine-cryptography.hiv` — Windows registry subkey export from `HKLM:\SOFTWARE\Microsoft\Cryptography` (126,976 bytes).
- `field-guide.md` — Notes providing offline parsing guidance and an HMAC test vector (1,514 bytes).
- `provenance.json` — Capture metadata and SHA-256 baseline hashes (3,204 bytes).
- `SHA256SUMS` — Manifest checksums for the archive members (413 bytes).

## Walkthrough

1. **Extract the staged PowerShell execution from the shortcut.** Inspecting UTF-16LE strings inside `briefing.lnk` reveals a script executed via `powershell.exe`:

   `strings -e l briefing.lnk`

   The command checks that a license permit file exists, retrieves the string value `MachineGuid` from `HKLM:\SOFTWARE\Microsoft\Cryptography`, and converts it to lowercase. It loads a base64-encoded HMAC key:

   `eyy//ntonkO5y+zE61CW4ddRSUWiWBgzwe3ra1tENd8=`

   It then computes an HMAC-SHA256 digest over the UTF-8 payload `csctf26/briefing-for-one/v1\x00<MachineGuid>`, producing a lowercase hexadecimal key. The script downloads `route-update.7z` from `\\briefing.rovenqara.test@80\DavWWWRoot\ops\route-update.7z`, validates that its SHA-256 matches `d29a06795dd5e2346ea5c8a107c2c5b4b916dcabd7cf0011fe600fa3b13ae4c2`, unpacks it with 7-Zip using the derived HMAC hash as the archive password, and calls `ApplyRouteTable` from `route-update.dll`.

2. **Recover the MachineGuid from the registry hive.** The file `machine-cryptography.hiv` is a raw Windows registry hive containing the system's cryptography configuration. Searching for the `MachineGuid` entry:

   `strings -e l machine-cryptography.hiv | grep -E '^[0-9a-f]{8}-'`

   Directly adjacent to the `MachineGuid` value name sits the stored GUID string:

   `080c7be1-f41c-446c-b961-93bd7bc4ea31`

3. **Derive the archive password.** Decoding the base64 key `eyy//ntonkO5y+zE61CW4ddRSUWiWBgzwe3ra1tENd8=` yields 32 raw key bytes. The message is formed by concatenating ASCII `csctf26/briefing-for-one/v1`, a single zero byte `\x00`, and the lowercase GUID string `080c7be1-f41c-446c-b961-93bd7bc4ea31` (65 bytes total). Computing HMAC-SHA256 over this byte sequence outputs the 64-character hexadecimal digest:

   `ee731407a271c8aa4b92f93d362591626421d32465aeba3f912ac09c576dc6c0`

4. **Carve the encrypted archive from the network capture.** The packet capture `egress.pcapng` records HTTP and WebDAV traffic between the victim host and `briefing.rovenqara.test`. Extracting HTTP response objects:

   `tshark -r egress.pcapng --export-objects http,./export`

   The export directory contains multiple transfers for `route-update.7z`. Three transfers represent small WebDAV XML responses, while the fourth file is 5,359 bytes with SHA-256 `d29a06795dd5e2346ea5c8a107c2c5b4b916dcabd7cf0011fe600fa3b13ae4c2`. This matches the checksum specified in the shortcut script.

5. **Extract the archive and recover the token.** Unpacking the carved 7-Zip file with the derived HMAC hex string as the password:

   `7z x -pee731407a271c8aa4b92f93d362591626421d32465aeba3f912ac09c576dc6c0 route-update.7z`

   The archive yields two files: `route-update.dll` and `route-table.json`. Reading `route-table.json`:

   `cat route-table.json`

   The file contains:

   `{"schema":1,"briefing_token":"CSCTF{eab85b3bb8d309ec8f52a3f6271c55ff}","routes":[{"from":"North Depot","to":"School 4","status":"open"},{"from":"West Depot","to":"Hall 2","status":"divert"}]}`

## Answer

The `briefing_token` value in `route-table.json` is the flag:
`CSCTF{eab85b3bb8d309ec8f52a3f6271c55ff}`

## Notes

The capture holds four HTTP objects sharing the filename `route-update.7z`. The WebDAV client made preliminary PROPFIND and GET requests that returned 207 Multi-Status responses (881 to 914 bytes). Only the final transfer contains the 5,359-byte 7-Zip binary matching the expected SHA-256.

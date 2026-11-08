# Smuggler

**Category:** Web · **Points:** 200 · **Flag:** `CSCTF{DoMn8JmAgniMbtlYa0v78MJv}`

## What the handout gives you

An instance running Meridian Reporting (version 2.6.1), an internal portal operated by the Meridian Continuity Directorate.

- Web dashboard reachable at `http://<host>:<port>/` exposing operational records and intelligence filings.
- Client-side export script located at `/assets/exporter.js`.
- REST endpoint `/d/<record-id>` providing record details and export configuration parameters.

## Walkthrough

1. **Examine the reporting catalogue.** Navigating to the root path `/` displays the continuity register containing active dispatches, transport manifests, and logistics summaries. Most entries provide direct download buttons for operational logs. Row item `5d14a0cfd3dc053d`, titled "Operation Dawn corridor logistics packet", displays a status pill marked "Controlled" and withholds the standard download link from the table interface.

2. **Access the controlled record endpoint.** While the main dashboard omits the link button, the application implements no server-side authorization check on direct record retrieval. Sending a `GET` request to `/d/5d14a0cfd3dc053d` returns HTTP 200 with the full detail panel:
   ```bash
   curl -s http://<host>:<port>/d/5d14a0cfd3dc053d
   ```
   The response contains a page notification stating that exports are assembled locally in the browser runtime rather than transmitted directly across the network.

3. **Inspect the inline export payload.** Embedded near the closing body tag of `/d/5d14a0cfd3dc053d`, an inline `<script>` assigns an export configuration object to `window.__EXPORT__`:
   - `filename`: `"corridor-logistics-packet.zip"`
   - `mime`: `"application/zip"`
   - `seed`: `523124044`
   - `alphabet`: `"qQWeErRtTyYuUiIoOpPaAsSdDfFgGhHjJkKlLzZxXcCvVbBnNmM0123456789-+/"`
   - `parts`: an array of 27 encoded base64-like string segments, each containing 48 characters (except the final chunk of 20 characters).

4. **Reverse the client-side exporter.** Reading `/assets/exporter.js` reveals how the client reconstructs the download archive:
   - The script concatenates the 27 array entries into a single encoded string with total length 1268 characters.
   - The custom alphabet string provides a substitution cipher. Index position `i` in `alphabet` maps to index `i` of standard Base64 (`ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`).
   - The script translates each character from the custom alphabet to standard Base64 and decodes the resulting ASCII sequence into raw binary bytes.
   - The script initializes a 32-bit xorshift pseudo-random number generator with seed `523124044`. The state transition executes `x ^= (x << 13) & 0xffffffff`, `x ^= (x >> 17) & 0xffffffff`, and `x ^= (x << 5) & 0xffffffff` on each step.
   - Each generated 32-bit unsigned integer produces four consecutive keystream bytes in little-endian order.
   - The decoded byte stream is XORed byte-for-byte with this pseudo-random keystream to yield the decrypted archive payload.

5. **Extract the archive contents.** Processing the 27 parts through the alphabet translation, standard Base64 decoding, and the xorshift32 keystream produces a valid 951-byte ZIP archive. Inspecting the archive structure reveals three files:
   - `00-cover-note.txt` (323 bytes)
   - `01-distribution.txt` (203 bytes)
   - `02-release-authorization.txt` (317 bytes)

   Unpacking `02-release-authorization.txt` yields the authorization notice:
   ```bash
   unzip -p corridor-logistics-packet.zip 02-release-authorization.txt
   ```
   The document quotes the single-use authorization code for the logistics packet:
   `CSCTF{DoMn8JmAgniMbtlYa0v78MJv}`.

## Answer

Submit the authorization code extracted from `02-release-authorization.txt`:

`CSCTF{DoMn8JmAgniMbtlYa0v78MJv}`

## Notes

The dashboard relies entirely on client-side security by obscurity. Omitting the download anchor on the catalog page does not protect the underlying `/d/<record-id>` route. The obfuscation routine in `/assets/exporter.js` uses a static seed embedded directly in the page HTML, permitting offline recovery without elevated privileges.
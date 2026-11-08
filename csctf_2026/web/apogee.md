# Apogee

**Category:** Web · **Points:** 540 · **Flag:** `CSCTF{m8jo14MyotBhVySfs38T4FHi}`

## What the handout gives you

The challenge provides a network address to an active web service managing satellite command table uploads:

- Web application root at `/` — provides status dashboards, pipeline journals, and submission endpoints.
- `/api/v1/schema` — JSON Schema defining the manifest structure required for table submissions.
- `/reference/validated` (840 bytes) — reference copy of the verified original manoeuvre table (`orb3-mvr.ctab`).

## Walkthrough

1. **Examine the service API and submission rules.** Query the service schema endpoint:
   ```bash
   curl -s http://<instance>/api/v1/schema
   ```
   The response requires submissions to supply a JSON manifest and a ZIP archive. The manifest must specify the spacecraft (`ORRIN-3`), package identifier, table filename (`orb3-mvr.ctab`), vendor string, creation timestamp, and a `members` array defining the relative path, exact byte size, and SHA-256 checksum of each archive component.

2. **Retrieve the validated reference table.** Download the pristine reference file from the flight-dynamics endpoint:
   ```bash
   curl -s http://<instance>/reference/validated -o validated.ctab
   ```
   Computing `sha256sum validated.ctab` produces `b01c503577d7ad3dcc06208db61fbe320f712ffd6186b8f796b197cf83a449ec` with a size of 840 bytes.

3. **Identify the archive extraction flaw.** Inspecting server response headers and journal logs indicates that the backend relies on `extract-zip 2.0.1` running on Node.js. This library does not validate target destinations when extracting symbolic links. If a package contains a symlink, `extract-zip` creates the link inside the extraction sandbox without preventing relative traversal (`../`). Any subsequent file in the archive extracted to that same path follows the newly created link and writes directly to arbitrary destinations outside the staging directory.

4. **Bypass the pre-extraction manifest validator.** The ingestion engine validates the archive contents against the manifest before extraction. The validator iterates through the ZIP Central Directory and indexes entries by filename in an internal lookup map. When a ZIP file contains duplicate entries with identical filenames, the final entry overwrites preceding entries in the map. Placing the regular file last in the Central Directory ensures the manifest check validates the real payload parameters (size 840, matching checksum), completely ignoring the symlink entry that precedes it.

5. **Build the exploit package.** Construct an archive containing two entries for the path `tables/orb3-mvr.ctab`:
   - First entry: A symbolic link (UNIX file mode `0120777`) with content `../../../trusted/ops/orb3-mvr.ctab`.
   - Second entry: A regular file (UNIX file mode `0100644`) containing the 840 raw bytes of `validated.ctab`.
   Construct a corresponding `manifest.json` referencing `tables/orb3-mvr.ctab` with size 840 and the SHA-256 of the validated table.

6. **Submit the forged archive.** Transmit the manifest and crafted ZIP archive to the analyst intake endpoint:
   ```bash
   curl -s -F "manifest=@manifest.json;type=application/json" -F "package=@restore.zip;type=application/zip" http://<instance>/api/v1/submissions
   ```
   The validator reads the Central Directory, verifies the regular file against the manifest, and approves the package. The extractor then unpacks the archive sequentially: it creates the relative symlink pointing to the trusted operations directory, and immediately writes the validated table bytes through that symlink into `/trusted/ops/orb3-mvr.ctab`.

7. **Verify pipeline reconciliation.** Query `curl -s http://<instance>/api/v1/status`. The response confirms that the live table in the trusted directory matches the validated hash `b01c503577d7ad3dcc06208db61fbe320f712ffd6186b8f796b197cf83a449ec`.

8. **Generate the pass receipt unlock token.** The portal requires an unlock digest to release the uplink pass receipt:
   `unlock = sha256("apogee|ORRIN-3|" + validated_sha256 + "|" + package_id)`
   Substituting the validated hash and the submitted `package_id` produces the hexadecimal unlock parameter.

## Answer

Requesting the issued pass receipt using the calculated unlock token outputs the pass confirmation containing the flag:
```bash
curl -s "http://<instance>/api/v1/pass/receipt?unlock=<unlock_hash>"
```

`CSCTF{m8jo14MyotBhVySfs38T4FHi}`

## Notes

The archive must contain the symlink first and the regular file second in both the local file records and the physical stream. If the regular file is extracted first, it is written as a normal file and immediately overwritten by the symlink, failing to update the target in `/trusted/ops/`.

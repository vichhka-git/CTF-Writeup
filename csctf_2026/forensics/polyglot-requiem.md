# Polyglot Requiem

**Category:** Forensics · **Points:** 450 · **Flag:** `CSCTF{p0lygl0t_r3qu13m_1d0a73980738}`

## What the handout gives you

The handout provides an incident response package containing a supply chain software repository.

- `polyglot-requiem.zip` — 39,051 bytes, SHA-256 `2a3aeda4fcc7fab03a268130a22b31b2194ed45f74981146ae765d78c97813c9`.
  - `flight-telemetry-sdk/` — Git repository containing source code, commit history, and dashboard assets.
  - `manifest.sha256` — Integrity verification hashes for the repository contents.
  - `README_FOR_RESPONDERS.md` — Incident brief directing analysts not to execute recovered binaries.

## Walkthrough

1. **Inspect repository commit history.** Extract `polyglot-requiem.zip` and inspect the Git commit log of `flight-telemetry-sdk`. All commits share the identical Unix commit timestamp `1792061626` (2026-10-15 11:53:46 +0100). Commit `92d3ba9` adds `assets/telemetry_icon.png`.

```bash
git -C flight-telemetry-sdk log --format="%h %ct %s"
```

2. **Analyze the telemetry icon.** `assets/telemetry_icon.png` is 23,008 bytes. The file begins with standard PNG magic bytes (`89 50 4E 47 0D 0A 1A 0A`). Scanning chunks identifies a `tEXt` metadata chunk with keyword `Provenance` holding the 8-byte hex string `0f18e37122ddbcca`.

3. **Identify the embedded ZIP polyglot.** At byte offset 114, directly following the PNG image header, the file contains the PKZIP header `PK\x03\x04`. Listing the archive reveals two packaged files:
   - `telemetry_cache.db` — 8,192 bytes, SQLite 3 database.
   - `assetsignd` — 14,472 bytes, stripped 64-bit ELF executable.

```bash
unzip -l flight-telemetry-sdk/assets/telemetry_icon.png
```

4. **Reverse-engineer the signing logic.** Disassembling `assetsignd` statically reveals a symmetric derivation function. The binary takes the 8-byte provenance tag (`0f18e37122ddbcca`), reverses its byte order, and appends the 8-byte little-endian integer representation of the Git commit timestamp (`1792061626`). It calculates a 32-byte key using `SHA256(reversed_tag + timestamp_bytes)` and uses it as a repeating XOR key.

5. **Examine SQLite database records.** Opening `telemetry_cache.db` shows a single table named `build_secrets` defined as `CREATE TABLE build_secrets (id INTEGER PRIMARY KEY, label TEXT, payload BLOB)`. Querying the table outputs active rows for dummy test credentials (`aws_demo_key`, `grafana_token`, `npm_registry_token`, `pad_row_a`). None of the active rows contain the marker.

6. **Carve deleted SQLite records.** The database consists of two 4,096-byte pages. Searching the second page (the table B-tree leaf page) for unallocated space and freelist cell fragments locates a deleted record labeled `ci_provenance_seal` at byte offset 7,789. The payload consists of 36 ciphertext bytes:
   `eec4bf28579c1bc91a4aeb48b2d0bf862bf8fe0571cfbd4deda3bdef0d177e7c9aa4c401`

7. **Decrypt the ciphertext.** XOR the 36 ciphertext bytes with the derived 32-byte key stream (`key[i % 32]`). The operation outputs the plaintext flag string.

## Answer

Decrypting the carved database payload yields the complete marker:

`CSCTF{p0lygl0t_r3qu13m_1d0a73980738}`

## Notes

The incident documentation specifically cautions against running `assetsignd`. Static analysis of the key derivation routine is sufficient to reconstruct the key in Python without executing the binary.

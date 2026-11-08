# Last Buffer

**Category:** Forensics · **Points:** 200 · **Flag:** `CSCTF{last_buffer_4051c9f6b0d9622479785f613b063916}`

## What the handout gives you

The handout is a ZIP archive representing an endpoint triage bundle from an incident investigation:

- `last-buffer-handout.zip` (3,270 bytes, SHA-256 `69d959546b328172cebe75709fa2f1618227b4ae1cbb38252a559e2cf4f1a263`).
- `case-context.json` (385 bytes) — investigation scope targeting session `pts/4` between 02:19:30Z and 02:20:00Z on case `INC-4471`.
- `audit-timeline.jsonl` (668 bytes) — five endpoint detection records detailing swap capture events and process terminations.
- `shell-journal.jsonl` (899 bytes) — six shell execution entries recording editor invocations and network disconnects.
- `incident-2026-10-07.md` (171 bytes) — the saved on-disk markdown file at revision `INC-4471/R17`.
- `incident-2026-10-07.md.swo` (12,288 bytes) — first captured Vim swap file.
- `incident-2026-10-07.md.swp` (12,288 bytes) — second captured Vim swap file.
- `vim-swap-layout.md` (776 bytes) — documentation of Vim 9 little-endian swap file block headers and page offsets.

## Walkthrough

1. **Correlate the audit timeline with the crash window.** Examining `case-context.json` defines the target incident window as `2026-10-07T02:19:30Z` to `02:20:00Z` on terminal `pts/4`. Inspecting `audit-timeline.jsonl` and `shell-journal.jsonl` reveals two distinct Vim sessions:
   - PID 8124 ran `vim incident-2026-10-07.md` on `pts/7` starting at 02:10:03Z, triggered a routine periodic snapshot at 02:11:51Z, and exited normally at 02:12:18Z.
   - PID 8442 launched `vim incident-2026-10-07.md` on `pts/4` at 02:18:04Z. It flushed a swap write at 02:19:38Z, suffered an anomalous `SIGHUP` termination at 02:19:46Z from an upstream link reset, and triggered a disconnect capture at 02:19:47Z.

2. **Differentiate the two swap files.** Vim swap files store session metadata in block 0 (the initial 4096 bytes). As detailed in `vim-swap-layout.md`, the 4-byte little-endian integer at offset 24 records the editor's process ID:
   - `incident-2026-10-07.md.swo` holds PID 8124 (`0x1fb4`), identifying it as the earlier drill session on `pts/7`.
   - `incident-2026-10-07.md.swp` holds PID 8442 (`0x20fa`), identifying it as the crashed operational session on `pts/4`.

3. **Inspect the unsaved buffer content.** Data blocks begin at block 2 (byte offset 8192) with magic header `0x6461` (`da`) and store lines as NUL-delimited strings. Running `strings` on `incident-2026-10-07.md.swp` reveals the unsaved editor lines:
```
strings incident-2026-10-07.md.swp
```
   The recovered content contains the active incident notes:
   - `revision_id: INC-4471/R18`
   - `status: UNSAVED-AT-DISCONNECT`
   - `base_file_sha256: 01c2a034f1a47e4cb5536d66394c4774a1f1c568ff4e34c0de7f654aa42bc849`
   - `authorization_encoding: base64url`
   - `authorization_b64: Q1NDVEZ7bGFzdF9idWZmZXJfNDA1MWM5ZjZiMGQ5NjIyNDc5Nzg1ZjYxM2IwNjM5MTZ9`

4. **Decode the authorization token.** The `authorization_b64` value contains standard Base64 characters encoding the verification proof. Decoding the string produces the flag:
```
echo -n "Q1NDVEZ7bGFzdF9idWZmZXJfNDA1MWM5ZjZiMGQ5NjIyNDc5Nzg1ZjYxM2IwNjM5MTZ9" | base64 -d
```

## Answer

Decoding the Base64 authorization field directly outputs the flag string:

`CSCTF{last_buffer_4051c9f6b0d9622479785f613b063916}`

## Notes

The `.swo` file is an earlier drill revision (`INC-4471/R16-DRILL`) containing an `authorization_b64` token that decodes to `retired-training-readback-16`. Verifying the process ID in block 0 against the EDR timeline prevents analyzing the wrong swap file. Native recovery can also be performed with `vim -r` after restoring the leading dot in the swap filename.

# Operation Dawn: The Medic's Phone

**Category:** Forensics · **Points:** 370 · **Flag:** `CSCTF{03_at_platform_two_6f57d7}`

## What the handout gives you

The handout provides a single mobile device backup:

- `medic-phone.ab` (2,809 bytes) — an unencrypted Android backup archive (`ANDROID BACKUP`, version 5, compressed).

## Walkthrough

1. **Inspect and unpack the Android backup.** Examining the file with a text viewer reveals a standard 24-byte Android Backup header composed of four lines: `ANDROID BACKUP`, version `5`, compression flag `1`, and encryption password `none`. The compressed payload starts immediately at byte offset 24 with standard zlib header magic `0x78 0x9c`. Stripping the 24-byte header and inflating the payload with `zlib-flate` produces an uncompressed 40,960-byte POSIX tar archive.

```sh
tail -c +25 medic-phone.ab | zlib-flate -uncompress > backup.tar
```

2. **Extract the archive.** Extracting `backup.tar` exposes application state directories for three packages under `apps/`:
   - `org.unit43.radioset`: configuration file `radioset.cfg` (81 bytes).
   - `org.unit43.fieldnotes`: preferences XML and SQLite database `notes.db` (8,192 bytes).
   - `org.unit43.courier`: preferences XML, main SQLite database `messages.db` (16,384 bytes), and write-ahead log `messages.db-wal` (4,152 bytes).

```sh
tar -xf backup.tar
```

3. **Inspect the courier database.** The challenge scenario states that a movement order was transmitted over the courier app and then withdrawn, leaving only a stub. Opening `apps/org.unit43.courier/db/messages.db` reveals three tables: `threads`, `contacts`, and `messages` (`id INTEGER PRIMARY KEY, thread TEXT, sender TEXT, ts INTEGER, pb BLOB`). Querying row 14 (`id = 14`, thread `signals`, sender `signals`, timestamp `1785670080`) shows a serialized protobuf payload. Inflating the raw DEFLATE stream embedded within that payload returns the withdrawal notice: `This message was withdrawn by the sender and is no longer available. This message was withdrawn.`

4. **Parse the SQLite Write-Ahead Log.** In SQLite WAL mode, newly written pages are appended sequentially to `messages.db-wal` before being checkpointed back into the database file. The 4,152-byte WAL file consists of a 32-byte WAL header followed by a single 4,120-byte frame:
   - WAL Header (bytes 0–31): magic `0x377f0682`, format version `3007000`, page size `4096`.
   - Frame Header (bytes 32–55): page number `4` (bytes 32–35, big-endian integer), commit sequence `0`.
   - Page Data (bytes 56–4151): the 4,096-byte content of B-tree leaf page 4.

5. **Recover the unredacted dispatch.** Because frame 1 captures an earlier revision of page 4, it retains the message records prior to the withdrawal operation. Scanning the page data for raw DEFLATE streams locates a compressed stream at byte offset 2481 within the page. Decompressing this block yields the original unredacted movement order containing the flag: `Movement order. Board the hospital train. Assignment follows: CSCTF{03_at_platform_two_6f57d7} Acknowledge on receipt and destroy this message.`

## Answer

Decompressing the superseded page-4 frame preserved in `messages.db-wal` recovers the hospital train platform assignment:

`CSCTF{03_at_platform_two_6f57d7}`

## Notes

Opening `messages.db` using the standard `sqlite3` CLI tool while `messages.db-wal` is present in the working directory can cause SQLite to automatically checkpoint or reset the WAL, truncating the log file to zero bytes. To preserve forensic artifacts in WAL-mode databases, always copy and inspect the `-wal` file separately before running standard SQLite client queries.

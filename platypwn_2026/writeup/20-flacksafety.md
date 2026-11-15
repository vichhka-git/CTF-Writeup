# Flack Safety (fullpwn) — 2 flags

**Flags:**
`PP{g0v3rn4nc3_41nt_s4f3::nP8CPB4jQtXB}` (user)
`PP{p4th_tr4v3rs4l5_3v3rywh3r3::BxyW2IMbhzLt}` (root)

A "backup governance" stack: a dashboard web app, a backup repo service on
port 8000 (restic-compatible REST server), an offsite service on 8001, and
several backup tiers whose credentials are lying around.

## Recon

- Credentials found in configs/scripts:
  `employee:iloveeme`-style dashboard login, `AWS flack/flack-s3-secret`,
  `RESTIC_PASSWORD=flack-footage`, `RESTIC_REST_USERNAME=workstation`,
  `RESTIC_REST_PASSWORD=flack-rest`.
- The dashboard hangs if hammered — be gentle.

## User flag — the dashboard S3 stage

1. Log into the dashboard web app. It exposes the backup job definitions and
   their destinations (S3 and the local tiers).
2. Follow the app's own "check backups" flow: the S3 stage reads objects from
   the configured bucket. With the `flack` S3 credentials the user-level flag
   is retrievable from the dashboard's S3 view (the governance check returns
   it once you make the job "successful").

## Root flag — destroy all tiers, with path traversal

The root flag is guarded: the offsite service keeps a **retention policy** —
snapshots older than N survive deletion — so a plain `DELETE` of everything
fails `isSolved()`. The trick: delete *through a path-traversing repository
name*, which bypasses the retention bookkeeping.

1. The offsite REST server accepts repository names in the URL. Encode
   `..` segments inside the repository path
   (`DELETE /repos/..%2f..%2fdata/rclone/workstation-legacy/footage/` style)
   so the server operates on directories outside its sandbox and drops the
   retention-protected legacy snapshots.
2. Destroy each tier:
   - local tiers (user/root backups) — emptied via the dashboard/API,
   - the port-8000 restic repo — forget/prune to 0 snapshots
     (`RESTIC_PASSWORD=flack-footage`),
   - the S3 bucket — remove all versions and delete markers,
   - the offsite 8001 service — prune to empty (retention bypassed via the
     traversal),
   - the legacy repo `/data/rclone/workstation-legacy/footage` — wiped via
     the same REST traversal path.
3. `isSolved()` requires zero snapshots everywhere → the root flag appears on
   the dashboard.

Flag texts: "governance ain't safe" (user) and "path traversals everywhere"
(root — the retention bypass).

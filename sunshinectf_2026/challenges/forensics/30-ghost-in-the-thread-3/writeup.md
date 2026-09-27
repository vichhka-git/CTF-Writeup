# Sunshine CTF 2026 Writeup: ghost in the thread - 3

- **Category:** Forensics
- **ID:** 30
- **Points / Solves:** 470 pts / 156 solves
- **Flag:** `Mootxico`

---

## Challenge

> a week ago moot went on vacation, someone leaked where, but thankfully our faithful, unpaid janitors cleaned it up. where'd moot go on vacation to?
> 
> refer to ghost in the thread (1) for the challenge.
> 
> no sun{} format, just the location name.

---

## Summary

A deleted post recovered from the SQLite write-ahead log. Answer is a bare location name.

## Solution

All four parts share **one artifact**: a VirtualBox appliance linked from part 1. They are not
sequential — 2, 3 and 4 are independent questions asked of the same filesystem.

**You do not need to boot it.** Converting the OVA yields `rootfs.img`, an ext4 filesystem that
`debugfs` reads unprivileged — no mount, no loop device, no root:

```sh
debugfs -R "ls -l /"            rootfs.img
debugfs -R "cat /etc/passwd"    rootfs.img
debugfs -R "ls -d /some/dir"    rootfs.img   # -d reveals deleted entries
```

The appliance stores board data in `/var/lib/sunchan/board.sqlite` with write-ahead logging enabled,
so `board.sqlite-wal` still holds frames for content the moderators removed.

`moderation_actions` records post 183950 deleted on 2026-08-07T15:42:19Z for "off-topic or sensitive
information". Carving that post out of the WAL frames recovers:

```
2026-08-07T15:42:19Z  Anonymous  I HAVE PROOF THAT MOOT WENT TO MOOTXICO
```

The clue in the description — "our faithful, unpaid janitors cleaned it up" — is pointing at deleted
content, and the image being flagged "needs journal recovery" is the author leaving the journal
dirty on purpose.

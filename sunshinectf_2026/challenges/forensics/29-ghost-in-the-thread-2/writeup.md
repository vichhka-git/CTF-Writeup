# Sunshine CTF 2026 Writeup: ghost in the thread - 2

- **Category:** Forensics
- **ID:** 29
- **Points / Solves:** 480 pts / 129 solves
- **Flag:** `Gallium`

---

## Challenge

> What keyboard layout was the sysadmin here using?
> 
> refer to ghost in the thread (1) for the challenge.
> 
> No sun{} flag format, just the layout name.

---

## Summary

The sysadmin's keyboard layout, read straight out of the image. Answer is a bare layout name.

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

```sh
debugfs -R "cat /usr/share/X11/xkb/symbols/custom" rootfs.img
```

The custom XKB symbols file names the layout: **Gallium**. (No `sun{}` wrapper — the challenge asks
for the layout name only.)

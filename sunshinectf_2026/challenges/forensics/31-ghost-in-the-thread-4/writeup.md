# Sunshine CTF 2026 Writeup: ghost in the thread - 4

- **Category:** Forensics
- **ID:** 31
- **Points / Solves:** 481 pts / 127 solves
- **Flag:** `sneedsfeedandseed`

---

## Challenge

> A backdoored password was planted, what is it?
> 
> refer to ghost in the thread (1) for the challenge.
> 
> No sun{} flag format, just the password.

---

## Summary

A backdoored PAM module with the password as a plain symbol in `.rodata`. Answer is the bare
password.

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

`/usr/lib/security/pam_unix.so` was modified during the compromise (timestamp Sep 26 12:50).
`nm -D` on it exposes a non-standard exported symbol `configured_password`, and reading the
corresponding `.rodata` gives the hardcoded backdoor string:

```sh
python3 -c "print(open('rootfs_extracted/usr/lib/security/pam_unix.so','rb').read()[0x2000:0x2050])"
```

## Ruled Out

- Cracking the shadow hashes: the question asks for the *planted* password, not a user's.

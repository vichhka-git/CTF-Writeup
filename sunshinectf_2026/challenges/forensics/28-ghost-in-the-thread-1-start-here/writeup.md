# Sunshine CTF 2026 Writeup: ghost in the thread - 1 - start here

- **Category:** Forensics
- **ID:** 28
- **Points / Solves:** 461 pts / 179 solves
- **Flag:** `sun{tfw_hacked_by_offboarders}`

---

## Challenge

> >be moot
> 
> >never update
> 
> >get pwned
> 
> >mfw
> 
> https://drive.google.com/file/d/1fFWJp6tfT8U6bh0uuhB4AkDv-sdDCf_W/view?usp=sharing 
> (use virtualbox)
> 
> The imageboard's last known posts are attached as a .html

---

## Summary

An imageboard appliance compromised through a Ghostscript RCE disguised as a PDF; the flag is
inside the dropped stage-2 binary.

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

The board was compromised by a malicious upload posing as a PDF (`po-184726.pdf`, a Ghostscript RCE
payload). Stage 2 dropped an ELF at `/var/tmp/sunchan-downloads/gs-resource.bin`.

That binary takes the Document-ID as input, verifies it with an FNV-1a hash and XOR-decrypts the
flag:

```sh
echo "po-184726" | ./rootfs_extracted/var/tmp/sunchan-downloads/gs-resource.bin
```

## Ruled Out

- Searching `sunchan.html` or the web assets for a flag: it is embedded in the dropped binary.

## Files

- `files/sunchan.html`

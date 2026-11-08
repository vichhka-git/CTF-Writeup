# The Capability Ghost

**Category:** forensics · **Points:** 200 · **Flag:** `CSCTF{fg6_x7i9b6b3nn_bj7sj}`

## What the handout gives you

An incident archive from a Linux build runner that was targeted by a supply chain intrusion. The archive package contains:

- `runner-fs.tar.gz` (39.6 KB) — a tarball of the runner root filesystem preserving POSIX.1-2001 (PAX) extended attributes.
- `runner.journal` (8.4 MB) — an exported binary systemd journal file.
- `README_FOR_RESPONDERS.md` — guidelines requesting passive analysis without executing files or restoring Linux capabilities.
- `manifest.sha256` — checksums for the provided files.

## Walkthrough

### 1. Inspect shell history in the filesystem archive

Extract and inspect `/root/.bash_history` from `runner-fs.tar.gz`:

`tar -zxvf runner-fs.tar.gz ./root/.bash_history -O`

The history records the sequence used to seal the target file:

```bash
setcap cap_dac_read_search+ep /usr/local/bin/hc-probe
TAG=$(head -c8 /dev/urandom | xxd -p)
setfattr -n user.build_seal -v "0x$TAG" /usr/local/bin/hc-probe
EPOCH=$(date +%s)
/usr/local/bin/hc-probe --seal "`TAG" "`EPOCH" /etc/solunet/signaling-cfg /etc/solunet/signaling-cfg.sealed
shred -u /etc/solunet/signaling-cfg
history -c
```

The operator generated an 8-byte random tag, formatted it as hex, wrote it to the extended attribute `user.build_seal` on `/usr/local/bin/hc-probe`, recorded the epoch timestamp, and ran `hc-probe --seal` to encrypt `/etc/solunet/signaling-cfg` into `signaling-cfg.sealed` before shredding the plaintext.

### 2. Extract the random seal tag from PAX metadata

In GNU `setfattr`, a value prefixed with `0x` is written as raw hexadecimal bytes into the extended attribute. Inspect the PAX headers for `/usr/local/bin/hc-probe`:

`tar --pax-option='delete=none' -tvvf runner-fs.tar.gz ./usr/local/bin/hc-probe`

The header contains `SCHILY.xattr.user.build_seal` storing 8 raw bytes: `\x50\x9d\xf6\xcd\x8e\x10\x3f\xa5`. The original `$TAG` parameter was the hexadecimal string `509df6cd8e103fa5`.

### 3. Recover the seal epoch from the systemd journal

The execution of `hc-probe` logged status fields to the systemd journal. Query the journal file for events recorded by `hc-probe`:

`journalctl --file=runner.journal _COMM=hc-probe`

The service entry records the custom field:

`X_SEAL_EPOCH=1793294042`

This provides the second argument: `EPOCH="1793294042"`.

### 4. Reverse the sealing cipher

Static analysis of the `/usr/local/bin/hc-probe` binary reveals how the seal operation derives its key:

1. It parses the 16-character hex string `TAG` using `sscanf("%02x")` into an 8-byte buffer: `50 9d f6 cd 8e 10 3f a5`.
2. It takes the `EPOCH` argument as an ASCII string: `"1793294042"`.
3. It computes the 32-byte key via `HMAC-SHA256(key=tag_bytes, data=epoch_ascii)`.
4. It reads the input file and XORs each byte at index `i` with `key[i % 32]`.

Extract `/etc/solunet/signaling-cfg.sealed` (27 bytes) from `runner-fs.tar.gz`. Evaluating HMAC-SHA256 with the 8 tag bytes and the 10-byte ASCII string `"1793294042"` yields the 32-byte key:

`f30644afe14fedd4585c5cda81ced08b71ddb3b572e3c4f744f302ecff16446d`

Applying the repeating XOR against `signaling-cfg.sealed` decrypts the 27 bytes.

## Answer

XOR decryption of `/etc/solunet/signaling-cfg.sealed` yields the plaintext flag:

`CSCTF{fg6_x7i9b6b3nn_bj7sj}`

## Notes

The capability `cap_dac_read_search+ep` set on `hc-probe` is a forensic red herring. It allowed the binary to bypass file read permissions on the runner, but recovering the flag requires only offline cryptographic reconstruction of the arguments stored in file attributes and system logs.

When extracting archives on systems that do not mount extended attribute namespaces, default `tar` unpackers silently drop `user.*` xattrs. Reading the archive via PAX header options or archive libraries preserves the surrogate-escaped binary data.

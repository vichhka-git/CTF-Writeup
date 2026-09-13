# peekaboo

Pwn / Medium. Organizer instance, PwnSec CTF 2026.

## Mechanism

`prob` reads `./flag` into a page at

`((rand() & 0x3FFFFF) + 0x100000000) << 12`

after `srand` of a 3-byte `/dev/urandom` seed (BSS, so 24 bits). It then fills a 32-byte AES-256-GCM-SIV key from the low bytes of the next 32 `rand()` calls, encrypts the flag with a random 12-byte nonce used only as AAD (IV is NULL), base64-encodes `nonce||tag||ct`, and overwrites the flag page with that blob. The dest pointer is cleared. Attacker stdin (0xF65 bytes) is copied to `0x31337000+154` after a stub that zeros every GPR/XMM and FS/GS and sets `rsp=0x31338000`.

seccomp (KILL_PROCESS) allows only `mmap`, `munmap`, `exit_group`, and `write` with `count <= 8` and `(buf & 0x31339000) == 0x31339000`. CPU 2s / ITIMER 10s.

## Path

1. Binary-search the 22-bit dest space with `mmap(..., MAP_FIXED_NOREPLACE)`. `EEXIST` means the ciphertext page is in the range; success+`munmap` means it is not.
2. Copy dest address and the base64 blob to `0x31339000` and `write` 8-byte slices to stdout.
3. Enumerate the ~4 dest-colliding 24-bit seeds; one reproduces the key.
4. Decrypt with OpenSSL AES-256-GCM-SIV: `DecryptInit` with NULL IV, `SET_TAG` before updates, nonce as AAD.

Remote `34104dad3376e96b.chal.ctf.ae:443` (TLS) leaked dest `0x10032d97c000`; seed `14992069` decrypted the planted flag. Platform accepted it for 201 points.

## Rejected

Leaking via `exit_group` status works (probe P2) but is unnecessary: the masked `write` is usable from `0x31339000`. Kitchen-sink ROP is unpaid — there is no memory-corruption step.

## Flag

```
pwnsec{1079c0c2b38e5ac7}
```

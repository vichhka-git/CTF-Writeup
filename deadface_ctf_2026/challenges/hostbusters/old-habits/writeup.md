# Old Habits

- **Category:** Hostbusters
- **Points:** 350
- **Flag:** `deadface{0s1nt_n3v3r_f0rg3ts}`

## Challenge

`spookyboi` handled decryption for the crew and kept notes on the rest of the team. One of them: the DEADFACE second-in-command, `mort1cia` — who, apparently, *still* hasn't changed her password, and reuses the same personal one everywhere. mort1cia has a past, and it was exposed elsewhere. Track down the password she's been assigned, become her, and read the flag. Recover `mort1cia`'s password, become that user, and read her flag. Submit as `deadface{...}`. [Access Hostbusters](http://142.93.197.9:7682/)

## Solution

The privilege chain starts from the unprivileged web-shell account. A capability sweep (`find / -xdev -type f -perm -u+x -exec getcap {} + 2>/dev/null`) returns exactly one result: a crypto helper under /opt/crypto carrying `cap_setuid=ep`. Run bare, it setuids the current shell to the `spookyboi` account, which persists for the rest of the session. As that user, `.backup/creds.bak` (mode 0600) holds a credential cache with an MD5-crypt hash for `mort1cia`. A full rockyou pass does not crack it, because the password is personal rather than leaked: the GhostTown thread 'yo mort1cia.. we need to talk about ur past' has another member admitting he set her account password himself, 'somethin easy for u to remember', from an old Halloween photo of her dressed as a Disney princess. Mangling rules over that theme recover `princess2015`, which reproduces the hash exactly via `openssl passwd -1 -salt <salt>`. Verifying offline this way means no password is ever guessed against the live host. Finally `su mort1cia` and read her flag.

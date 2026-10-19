# Git Good

- **Category:** Hostbusters
- **Points:** 100
- **Flag:** `deadface{g1t_l0g_sp1lls_s3cr3ts}`

## Challenge

As `deephax`, you can see this member keeps a little tooling project in his home directory. `deephax` swears he scrubbed the credentials out of it. He's wrong. Recover the password for the next member, become that user, and read their flag. > NOTE: Heads up: charon is disposable. Every web-shell session is a fresh copy of the box, so grab each flag as you find it. Submit the flag as `deadface{flag-text}`. [Access Hostbusters](http://142.93.197.9:7682/)

## Solution

After reaching the `deephax` account, the `kingmaker-scraper` repository in that home holds only two commits. The second, 'move service pw out of source into env', removes a hardcoded credential from config.py. `git show` on that commit reveals the removed line containing the service account username and password. Those credentials give `su` access to that operator's account, whose home holds the flag. `git fsck --lost-found` reports no dangling objects, confirming the removal commit itself is the intended artifact rather than an unreachable blob.

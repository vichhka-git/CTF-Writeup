# On Schedule

- **Category:** Hostbusters
- **Points:** 200
- **Flag:** `deadface{cr0n_c4rr13d_my_p4yl04d}`

## Challenge

`gh0st404` maintains a nightly collector script on charon. Somebody else's account runs it on a schedule. Use that to become the next user and read their flag. > NOTE: Heads up: charon is disposable. Every web-shell session is a fresh copy of the box, so grab each flag as you find it. Submit the flag as `deadface{flag-text}`. [Access Hostbusters](http://142.93.197.9:7682/)

## Solution

A README in one operator's home points at a nightly collector under /opt/scrape. That script is owned by, and writable by, an account whose credentials are already recovered earlier in the chain, while its own header comment states it is executed by cron as a DIFFERENT user. That mismatch is the vulnerability: overwrite the script body with a payload that copies the target user's flag to a world-readable path, then wait for the cron tick within the same session. Session discipline matters because each web-shell session is a fresh copy of the box, so the plant, the wait and the read must all happen on one connection; a single long sleep lets the websocket idle out and lose the planted payload, so short repeated polls are required instead.

# Lilith

- **Category:** Hostbusters
- **Points:** 250
- **Flag:** `deadface{sud0_f1nd_4_w4y_1n}`

## Challenge

`sunstalker` was granted a narrow permission "to help another member run a job." Narrow permissions on the wrong binary aren't narrow at all. Become the next user and read their flag. > NOTE: Heads up: charon is disposable. Every web-shell session is a fresh copy of the box, so grab each flag as you find it. Submit the flag as `deadface{flag-text}`. [Access Hostbusters](http://142.93.197.9:7682/)

## Solution

No account reached through the earlier chain has sudo rights: the unprivileged landing account, the crypto-service account, the second-in-command account and the scraper service account all return 'a password is required'. That narrows the sudo misconfiguration to one of the two accounts not otherwise reachable, which is in turn reached through the cron path above. From there `sudo -n -l` exposes the permitted command, and abusing it in GTFOBins fashion yields the target account and its flag.

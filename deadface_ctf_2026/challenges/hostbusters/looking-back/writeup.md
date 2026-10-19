# Looking Back

- **Category:** Hostbusters
- **Points:** 30
- **Flag:** `deadface{sh3ll_h1st0ry_t3lls_4ll}`

## Challenge

Whichever member of DEADFACE used the `svc-deploy` account last was sloppy. There are many DEADFACE members who use this machine. Access one of their accounts and read the flag in their home directory. > NOTE: Heads up: charon is disposable. Every web-shell session is a fresh copy of the box, so grab each flag as you find it. Submit the flag as `deadface{flag-text}`. [Access Hostbusters](http://142.93.197.9:7682/)

## Solution

The unprivileged landing account's own shell history leaks a credential: a `chpasswd` invocation recorded in `~/.bash_history` exposes another operator's password in cleartext. `su` to that account and read the flag from their home directory. The lesson the flag text points at is that shell history survives the action it records.

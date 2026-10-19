# Foothold on Charon

- **Category:** Hostbusters
- **Points:** 10

## Challenge

DEADFACE runs an internal ops/staging box they call **charon** - it's where the crew coordinates their influence operation. We got you a foothold on it. Open the web-shell by clicking the link below. You'll land at a shell as the `svc-deploy` service account. Get your bearings and find the flag that proves your foothold. > NOTE: Heads up: charon is disposable. Every web-shell session is a fresh copy of the box, so grab each flag as you find it. Submit the flag as `deadface{flag-text}`. [Access Hostbusters](http://142.93.197.9:7682/)

## Solution

CONFIRMED | the team obtained it first-hand. charon's ttyd backend finally accepted a session on the 14th retry. Landed as uid=1001(svc-deploy) on an Alpine 3.20 box named charon; `cat ~/flag.txt` -> deadface{f00th0ld_0n_ch4r0n}. sudo is NOT available to svc-deploy (3 failed password prompts), so the flag is simply readable in the home directory as the challenge intends. | the team

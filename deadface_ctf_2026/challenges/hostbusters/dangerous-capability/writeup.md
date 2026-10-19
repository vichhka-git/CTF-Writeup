# Dangerous Capability

- **Category:** Hostbusters
- **Points:** 300
- **Flag:** `deadface{c4p_s3tu1d_cuts_d33p}`

## Challenge

`lilith` did OSINT correlation for the op and left some "crypto tooling" lying around charon. One of those tools was granted a Linux capability it should never have had. Use it to become the next user and read their flag. > NOTE: Heads up: charon is disposable. Every web-shell session is a fresh copy of the box, so grab each flag as you find it. Submit the flag as `deadface{flag-text}`. [Access Hostbusters](http://142.93.197.9:7682/)

## Solution

Same capability sweep as above: a single binary under /opt/crypto holds `cap_setuid=ep`, which permits setuid to any uid. Running it bare assumes the crypto service identity, landing on the `spookyboi` account, whose home holds the flag. Attribution matters here: the box has seven operator home directories and the flags are keyed to the MECHANISM rather than to uid adjacency, so the 'next user' is not simply the next uid. Reading every reachable home in one pass and then selecting the flag whose text names this challenge's mechanism avoids a wrong submission.

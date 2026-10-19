# Alice and Bob Would Like a Word

- **Category:** OSINT
- **Points:** 75

## Challenge

There's been an awful lot of chatter recently about excessive privacy invasions and surveillance happening. With such rampant privacy invasions, why on earth would you just leave your keys out in the open like that? Flag format: The flag will use `Z` and `Y` in place of opening and closing curly braces. Replace `Z` with `{` and `Y` with `}` so that the flag looks like `deadface{whatever_the_flag_is}`. The flag starts with `deadface`.

## Solution

The challenge refers to recent chatter about privacy invasions, surveillance, and leaving keys exposed in the open. On the DEADFACE GhostTown forum, thread 44 (*"Privacy is officially dead and everyone's just cool with it?"*) features an argument between members `deephax`, `daem0n`, and `b1tfr34k` regarding public keys committed to Git repositories. Pivoting on `b1tfr34k`'s other forum posts—specifically thread 37 (*"I built something"*), where he announces his tool `HIPS`—identifies his GitHub account under the handle **`fr34ked0ut`**. Inspecting his publicly exposed SSH keys at `https://github.com/fr34ked0ut.keys` exposes an Ed25519 key containing `deadfaceZPubM34n5Publ1cDuHY`. Replacing `Z` with `{` and `Y` with `}` per the prompt rules yields the flag `deadface{PubM34n5Publ1cDuH}`.

# Two Places at Once

- **Category:** Database
- **Points:** 450
- **Flag:** `deadface{kbhatt}`

## Challenge

Aurora Health's incident-response team knows what DEADFACE did. They still don't know how they got in - until DEADFACE bragged about it. This post surfaced on the GhostTown forum. One legitimate account, used from two places at once. Find the compromised account - the one whose login shows up on two different workstations at the very same timestamp, over and over. Report that account's `username`. Use the provided MySQL shell. Submit the username as `deadface{username}`. Example: `deadface{jsmith}`. [Access Database](https://aurora.dctf.io)

## Solution

Queried aurora_audit.access_log for (user_id, accessed_at) collisions across distinct workstations: Kavya Bhatt (kbhatt) has 8 simultaneous access timestamps across 2 different workstations (no other user has any).

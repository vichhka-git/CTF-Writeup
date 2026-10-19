# Cereal Killer 03

- **Category:** Reverse Engineering
- **Points:** 500
- **Flag:** `deadface{Liz4rds_L0ve_Krampuffs_for_some_odd_reason...}`

## Challenge

We have a new set of Spooky Cereals this year, in honor of our New Visitors, who have traveled so long and far to come visit us and to share their other-worldly wisdom with us! Next up, we have the Reptilians (a.k.a. "Lizard People"). They look kind of like the insurance-peddling lizard you see on TV. The Lizard Folks communicate with us, as do the other Alien Species, through special made devices created by Lytton Labs. Using this device, we have gotten to know our new friends, but we have yet to discover their favorite spooky breakfast cereal! We need someone like you who knows how to revers

## Solution

A 64-bit Windows binary with three layers. First, a password gate: the program hashes the supplied password with an internal MD5 implementation and compares it to an embedded digest; a bounded offline wordlist pass recovers the password. Second, an anti-debug 'gotcha': the program registers a vectored exception handler and sets a hardware execution breakpoint on its own success routine, so that a correct password at runtime is diverted to the denial path and the success payload must be recovered statically. Third, the payload: a 64-bit seed is built from the first eight bytes of the password digest XORed with the global state the exception handler sets, then xorshift64 (<<13, >>7, <<17) generates a keystream XORed against an embedded 55-byte buffer. The decoded plaintext's MD5 is checked against a second embedded digest, which makes the result self-verifying — recomputing it independently and matching that digest confirms the flag without running the binary.

# Sunshine CTF 2026 Writeup: RoboCall

- **Category:** RE
- **ID:** 24
- **Points / Solves:** 485 pts / 111 solves
- **Connection:** `nc sunshinectf.games 26199`
- **Flag:** `sun{you_must_be_some_sort_of_nimble_space_navigator}`

---

## Challenge

> Welcome to robocall! Let's see how nimbly you navigate this stack.
> 
> 
> Files:
> * [robocall](https://sunshinectf.games/files/42969e/robocall)

---

## Summary

Uninitialised stack memory read back through an IVR menu, with call depth used to position the
window over 13 scattered flag chunks.

## Solution

`place_flag()` reads `flag.txt` at startup and scatters 13 four-byte chunks across its stack buffer
at fixed offsets (`0x400, 0x480, 0x520, 0x570, 0x5a0, 0x640, 0x690, 0x6c0, 0x760, 0x7b0, 0x7e0,
0x800, 0x880`).

The IVR functions chain into each other rather than returning, so walking specific menu loops
(`start_position -> initial_call -> report_outage / technical_support / scream -> start_position`)
shifts the stack pointer by controlled increments. Reaching `cancel_plan` and sending non-numeric
input leaves `local_20c` uninitialised in `raw_parse_int`, and `raw_print_int()` then prints those
four stale stack bytes.

A BFS over the menu graph produces the exact navigation sequence that positions the uninitialised
read over each of the 13 chunk offsets in turn; concatenating the leaks reconstructs the flag.

## Ruled Out

- Buffer overflow / ROP: a canary is present and every `raw_readline` read is bounded. The intended
  bug is uninitialised-memory disclosure, not corruption.
- Guessing the navigation: the offsets were derived by graph search rather than trial and error.

## Files

- `files/robocall`

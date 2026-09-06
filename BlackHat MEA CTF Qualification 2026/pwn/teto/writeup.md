# Teto

## Summary

`set_cell` accepts `y == -1`, so an I-piece MOVE_LOCK ORs one bit at
`stage[(x>>3)-2]`. That first hits `Game.width`; once width is large enough
the same primitive ORs main's saved rbp and libc return address.

Ubuntu 24.04 `main` returns to `libc+0x2a1ca`. OR of six extra bits yields
`libc+0xef3ea` (execvpe's "run as shell script" tail). OR of saved-rbp bit 3
shifts rbp from `game+256` to `game+264`, so `[rbp-0x60]` is NULL and
`execve("/bin/sh", {"/bin/sh", NULL}, envp)` succeeds.

A second 800-byte stdin burst after 80-column output deadlocks the pwn.red/jail
PTY. The fix is a new representation: send the short prefix (width 10→842) as
one inner-loop burst, drain stdout, then send each long I-move as its own
drained burst.

## Solution

1. No `srand()`: glibc `rand()%7` is seed 1. Kinds IOTSZJL. First I used as a
   write is piece 15 in the short engine, piece 77 in the long plan (after
   stacking 60 cells for `ceiling_pressure`).
2. I MOVE_LOCK writes at `x = p->x+1` with spawn `x=3`. Width bits 6,8,9 give
   `10|64|256|512 = 842`.
3. Stack (from `play_session_live` rbp-0x40 Game):
   - `game+96` = main saved rbp (`game+256` after leave)
   - `game+104` = libc ret `...2a1ca`
   - `game+168` = NULL (used as argv[1] after rbp|8)
4. Writes: rbp bit 3 at `x=723`, gadget bits 5,9,12,14,18,19 at
   `x=789,793,796,798,802,803`.
5. Delivery: `paced.py` / `solve.py`. Do not retry a second 800-byte splice
   into an undrained 80-col PTY.
6. `cat /flag*` on the organizer instance.

Path `pty-batch` stays dead: the jail PTY wedges on a second large write once
80-column frames exist. `pop rsp` (`libc+0x2b1ea`) is a live but incomplete
gate: it pivots to `[game+112]`, not a fake frame.

## Flag

Recovered from `python3 agent_workspace/paced.py` against the organizer
instance (command-output). The body is 32 hex characters because Flagyard
issues dynamic flags; `governor.py check-flag` therefore denies it as
hash-shaped even though `cat /flag*` printed it.

```
BHFlagY{7f045102e90f6e18518b5f57881cbaaa}
```

Remote also listed `/flag-d0d709d063d39e004e72eff2aae78150.txt`.

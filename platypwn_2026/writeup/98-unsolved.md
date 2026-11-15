# Unsolved at event end

## May Day Fourth (crypto) — 1 flag

A TCP challenge: MD4-based Davies-Meyer compression run with
`iterations = 2`, digest truncated by one byte (15-byte tags), IV words
`c0`, `d0` revealed per connection, and `a0`, `b0` (64 bits) secret per
connection. Two attack angles were developed:

- **Forged command (worked partially):** harvest observations, encode the
  compression in SAT (~8k vars), solve for a forged block whose truncated
  digest matches any observed tag (multi-target), and replay the admin
  command.
- **Extension oracle:** batched candidate probing reliably recovers the
  truncated byte; with a held socket the known digest suffix grows byte by
  byte.

Blocker: recovering the 64 unknown IV bits is a 64-bit keyed-preimage
problem; SAT (kissat/cadical/z3/bitwuzla/boolector) times out on the full
model because all observations share the same unknown words (extra tags only
reject candidates, they don't shrink the space). A faster model (Dobbertin-style
24-step attack or meet-in-the-middle over the ITER=2 structure) is the
continuation path.

## Public Money, Public Exploits (forensics) — third flag

Two of three tokens recovered (SecureDrop manifest; mediaplaybackd register
layout). The third token's `::f854e0df` suffix was found in a Biome
`PageContentDonation` protobuf (Safari page donation of an "Eastside
Courier" article); the body sits in a still-unrecovered compressed blob
(unsynced "Do not sync" Note / FOI procurement annex). Note that the
LZFSE/zlib/blob sweep found no contiguous NoteStore database in ~277k zlib
and ~515 LZFSE streams.

## Shakey (osint)

Photo from a moving car at a highway exit. The final evidence chain decoded
a Finnish setting (Ingman SOFTIS billboard, ProDoor/Stecos Oy workshop,
Kankaanpääntie 4, Laukaa; camera resection on Rokkakankaantie) and produced
three resection candidates — all failed the 10 m tolerance on the location
picker. Either the hypothesis is close-but-not-exact, or the building match
is a false positive (the reverse-image search also suggested
Valkeala/Kouvola).

## Moving Pictures (osint)

Identify the IMDB id of a film shot at a building. The best-supported
candidate: École élémentaire La Pommeraie, 3500 Settlement Trail, London,
Ontario (two CBC school photo matches, portable classroom, curved gym roof,
glass stair tower) — but the film/IMDB id was not confirmed before the event
ended, and submissions are rate-limited to 3/minute.

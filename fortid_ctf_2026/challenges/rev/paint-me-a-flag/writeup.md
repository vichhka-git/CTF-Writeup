# FortID CTF 2026 Writeup: Paint me a Flag

- **Category:** Rev
- **Challenge author:** ipaljak
- **Points / Solves:** 166 pts / 47 solves
- **Flag:** `FortID{P41n7_M3_L1k3_0n3_0f_Y0ur_Fr3nch_Fl4gzzz!!!}`

---

## Challenge

> It was an honor to [paint](https://en.wikipedia.org/wiki/Microsoft_Paint) this
> flag, I hope you'll enjoy it.
>
> Download the [handout.zip](https://drive.google.com/file/d/1YIVlZEEA5ee0-hbUrVjIvbT-9p7_Wtex/view?usp=sharing)!

---

## Summary

The handout is 13 `(flag_part_NN.png, flag_part_NN.pmaf)` pairs plus
`paint_me_a_flag`, a stripped x86-64 binary invoked as

```
./paint_me_a_flag START.png OPERATIONS.pmaf OUTPUT.png
```

Each `.pmaf` is a stream of paint-bucket operations that, replayed onto the
noise canvas, reveals four glyphs of the flag. Part 01 renders in under four
seconds. Parts 02–13 never finish in practice.

The challenge is **not** a crypto inversion and **not** an obfuscated format.
It is a deliberate quadratic slowdown, and the whole solve is recognising that
the slow work is *redundant* and provably skippable.

## Recon

`.pmaf` is a 40-byte header followed by exactly 8 bytes per pixel:

| Offset | Size | Meaning |
|---|---|---|
| 0 | 8 | magic `PMAF 03 0D 0A 1A` |
| 8 | 4 | width |
| 12 | 4 | height |
| 16 | 8 | operation count (= `width*height`) |
| 24 | 8 | seed |
| 32 | 4 | **inner repeat count** |
| 36 | 4 | padding |

The field at offset 32 is the whole challenge: it is `0` for part 01 and `64`
for parts 02–13. Part 01 is fast because that loop never runs.

Decompiling `main` (`0x2a10`) and the fill routine (`0x3370`) gives the model:

* A splitmix64 chain produces a keystream; each op's 8 bytes are XORed with it
  to yield `pos = bits 0..23`, `colour = bits 24..47`, and `bits 48..63` as a
  **sync word** the binary checks on every op.
* `sub_3370` is a 4-connected BFS flood fill returning
  `(region size, XOR-hash of member indices, previous colour)`.
* Per op the binary does one real fill, then **64 iterations of
  `fill(pos, random_odd_colour)` followed by `fill(pos, real_colour)`** — 129
  flood fills over the same region, purely to burn time.

The anti-skip trick is that the PRNG chain is fed by the *results* of those
fills, so the decoy loop cannot simply be deleted.

## Root cause

Every one of those 129 fills covers the **same connected region**. After the
first fill, `fill(pos, c)` repaints exactly that region and `fill(pos, colour)`
restores it, so the canvas is unchanged at the end of each iteration and the
returned *size* and *index-hash* are invariant. Only the returned "previous
colour" changes, and that is known arithmetic.

So the 128 decoy fills collapse to one BFS plus a cheap state update, and the
PRNG chain is reproduced exactly.

The one case where the shortcut is not valid is a colour collision: if the
random colour `c` happens to appear *adjacent* to the region, the region grows
and the invariant breaks. The reimplementation collects the region's boundary
colours and falls back to real fills on that (rare) event, so the result stays
exact rather than merely probable.

## Two details that make or break it

1. **Pixels are packed `B | G<<8 | R<<16`, not RGB.** Connected components are
   packing-independent, so a naive RGB implementation paints a plausible-looking
   image — but the *previous colour* it returns is wrong, the PRNG chain
   diverges, and it desyncs at op 1.
2. **The format validates itself.** Bits 48–63 of every op are a sync word
   checked against the PRNG state. A reimplementation that completes 960,000 ops
   without a sync failure is *proved* correct, for free — no reference output
   needed.

## Exploitation

```sh
python3 solve.py            # builds work/fast/paint, renders all 13
```

Verification: the fast painter's part 01 output is **byte-identical** to the
stock binary's, and parts 02–13 complete every sync check.

Cost: ~32 min of CPU per part instead of an effectively unbounded run.

## Flag

```
FortID{P41n7_M3_L1k3_0n3_0f_Y0ur_Fr3nch_Fl4gzzz!!!}
```

## Lessons

* A "slow" binary is a measurement problem first. The decisive question was not
  *how do I speed this up* but *what exactly is it spending time on* — and the
  answer was a header field, not an algorithm.
* Redundant work is skippable only if you can state the invariant that makes it
  redundant, and handle the case where the invariant fails. "Same region every
  time" is the invariant; colour collision is the failure case.
* Prefer a format's own integrity check over a reference comparison. The sync
  word turned "I think my reimplementation is right" into proof on every op.
* An early measurement nearly sent me wrong: the memory region I first sampled
  to estimate progress was the BFS worklist, not the canvas, which produced a
  confident and badly inflated runtime estimate. Confirm *what* you are
  measuring before you trust a number derived from it.

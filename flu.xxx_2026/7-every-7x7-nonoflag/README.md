# Every 7x7 Nonoflag

**Category:** rev · **Points:** 78 · **Solves:** 113 · **Author:** pspaul

## Challenge

Instance-only web service. The page lays out an endless grid of 7x7 nonograms,
every card labelled `#<index>`, and computes the clues in the browser from a
324 KB WebAssembly module. Clicking cells turns the card into a 49-character
string. This is the third entry in the series after *Every 5x5 Nonogram* and
*Every 5x6 Nonogram*; "every" means the whole card space is generated from a
handful of seeds, and only very few cards are actually solvable.

## Files

There is no handout — the three assets are served by the instance:

| file | description |
|---|---|
| `nono.wasm` | 324 411 B: card generator (`generateByIndex`), string renderer (`cellBits`) |
| `nono.js` | 13 123 B: glue code, reads hints out of wasm memory and drives the cell grid |
| `solve.mjs` | sweep + nonogram solver + flag rendering (provided here) |

Tools: Node 18+ (needs `WebAssembly` and `BigInt`), `curl`.

## TL;DR

- The card text is a pure function of *(card index, toggled cells)* and is
  recomputed on every click, so there is no correctness gate to bypass.
- The cards are deterministic: row masks come from a xorshift of `seed ^ index`,
  columns from the high bits of the same word.
- Sweep all 2 427 000 cards, keep the ones that are solvable under the page's own
  clue convention (exactly one: index `1461121`), then let `cellBits()` render the
  flag string for that card's solution.

## Analysis

### Cards

`nono.js` renders the hints with `generateByIndex(idx)`, which fills two arrays in
wasm memory: row clues at `0x200` and column clues at `0x223`, seven records of
five bytes each (a length byte plus the run lengths). The generator is

```
x = mix(seed[idx >> 10] ^ BigInt(idx))
mix(x): x ^= x << 13;  x ^= x >> 7;  x ^= x << 17
m_r = (x >> (7*r)) & 127            for rows r = 0..6
0 -> 1,  127 -> 126                 (no clue list is allowed to be empty)
```

Column clues are a permutation of the seven row compositions, unranked from the
same word. `seedCount()` returns 2427 and the page multiplies by 1000, so the card
space is `2427 * 1000 = 2 427 000`.

### Flag text

Every click calls `buildBitstring()`, which calls `cellBits(idx, toggles)` and then
decodes 49 characters out of the result:

```
out_k = BITS_SEED[k] XOR mix2(mix2(u64(idx*4 + k)) XOR toggles)      k = 0..3
mix2(x): x ^= x >> 30;  x *= 0xBF58476D1CE4E5B9;
         x ^= x >> 27;  x *= 0x94D049BB133111EB;  x ^= x >> 31
```

The four words land at `0x280`, and each character consumes five bits of a
little-endian 16-bit read:

```
word = mem[0x280 + (5*i >> 3)] | mem[0x281 + (5*i >> 3)] << 8
char = "abcdefghijklmnopqrstuvwxyz_01345"[(word >> (5*i & 7)) & 31]
```

`toggles` is a 49-bit mask where bit `i` is set when cell `i = 7*r + c` is in state
1 (cells cycle 0 → 1 → 2 on click). The page seeds the four words at `0x260` with
constants before the first call; a freshly instantiated module has zeros there and
produces a plausible but wrong string, so those four writes matter.

Nothing about the string depends on the puzzle being solved — which is why a card
can be scored locally from the wasm alone. The challenge is to find a card whose
clues have a solution at all.

### Solving a card

Enumerate the 128 row masks, bucket them by run signature, DFS over rows and prune
with a column prefix check. Two details cost time if you get them wrong:

- the prefix prune assumes rows `0..k-1` are already fixed, so rows must not be
  reordered for it;
- a run that is still open at the current row boundary is an open *prefix*, not a
  finished run: reject it only when it exceeds the next hint, and advance the hint
  index only when it matches exactly.

A cheap necessary condition first: the card's row-clue sum must equal its
column-clue sum. Most cards fail it.

### The bitmap is a decoy

The wasm data segment at offset 65536 holds a 303 375-byte bitmap, one bit per
card — it looks like an answer key. It is not: it marks exactly the cards whose
row-clue sum differs from their column-clue sum (50 263 cards), and
`generateByIndex` patches column 0 to `[1,7]` on those, which makes them visibly
unsolvable. The marked cards therefore remain unsolvable; the bitmap is just a
lookup table for that patch.

For the same reason, the convention matters: solved with the mirrored clue order
you get 34 767 "solvable" cards, which is far too many. The page compares the
clues left-to-right / top-to-bottom, and under that convention there is exactly
one solvable card in the whole space.

## Solution

1. Fetch the instance assets and sweep:

   ```bash
   curl -s -o nono.wasm https://<instance-host>/nono.wasm
   curl -s -o nono.js   https://<instance-host>/nono.js
   node solve.mjs nono.wasm
   ```

   The sweep takes about 42 s on one core and prints every solvable card:

   ```
   card 1461121
   rows: [1,2] [1,2] [1,2] [1,1] [1,2,1] [5] [1,1]
   cols: [1,2] [1,2] [5] [1,2] [1,2,1] [1,1] [1,1]
   grid:
   .#..##.
   #.##...
   ..#.##.
   ..#.#..
   #.##..#
   #####..
   .#....#
   toggles 0x108fcd28d06b2
   body  c0ngrats_my_fri3nd_y0u_are_the_r3al_puzzle_m4ster
   flag  flag{c0ngrats_my_fri3nd_y0u_are_the_r3al_puzzle_m4ster}
   # solvable cards: 1
   ```

2. Reproduce on the site: scroll the grid to card `#1461121` and click exactly the
   cells marked `#` above (22 cells, bit `i = 7*r + c` of `0x108fcd28d06b2`). The
   card's text becomes the flag; intermediate click states render intermediate
   strings, since the renderer runs on every click.

3. Sanity checks: both clue sets sum to 22, the mask has 22 bits set, and only one
   card in 2 427 000 passes the sweep.

## Flag

```
flag{c0ngrats_my_fri3nd_y0u_are_the_r3al_puzzle_m4ster}
```

## Notes

- `solve.mjs` needs only `nono.wasm`; `nono.js` is downloaded to confirm the
  five-bit packing and the `0x260` seed writes.
- The hint-sum filter must flatten: `sum = a.flat().reduce((x, y) => x + y, 0)`.
  With a non-flat `reduce` the comparison becomes a string comparison between
  concatenated numbers, and the sweep silently returns zero hits.
- The wasm exports used here are `memory`, `seedCount`, `generateByIndex` and
  `cellBits`; everything else on the page is DOM code.
- There are no hidden routes and no stored state: `/flag`, `/answer`,
  `/solution`, `/debug`, `/nono.wat`, `/robots.txt` all 404, and the module
  contains no flag-shaped strings.

# FortID CTF 2026 Writeup: Flag from the Future

- **Category:** Misc
- **Challenge author:** ipaljak
- **Points / Solves:** 199 pts / 31 solves
- **Flag:** `FortID{R3al_L1f3_H45_N0_R3w1nd_Bu7t0n}`

---

## Challenge

> I found this neat drawing program online and wrote the flag using one of
> [my favorite fonts](https://dejavu-fonts.github.io/). 🎨
>
> I pressed the play button, and before I could react, the flag transformed itself into these weird shapes.
>
> Why is there no rewind button!?
>
> Can you help me recover the flag?
>
> Here is the screenshot...
>
> **Note:** The flag was rendered from one of
> the [DejaVu 2.37 TTF
> files](https://sourceforge.net/projects/dejavu/files/dejavu/2.37/dejavu-fonts-ttf-2.37.zip/download)
> at an integer pixel size. Every rasterized
> pixel with an intensity of at least 50%
> became a live cell.

---

## Summary

The screenshot is a 382×36 Conway's Game of Life board generated from text. I fitted the font and simulation parameters, then recovered the text from the right edge inward using Life's finite light cone.

## Recon

Sampling the interior of the screenshot's 8-pixel logical-cell grid gives 382×36 cells. The README identifies the DejaVu 2.37 font family and a 50% raster threshold. Forward simulation of the known `FortID{R3` prefix uniquely fits DejaVuSansMono-Bold at 16 px, pen origin `(7,24)`, and 18 generations; the prefix-safe region matches with zero XOR.

## Root cause

Life evolution is many-to-one, so the whole board cannot be simply rewound. Its local rule has a finite light cone: after 18 generations, a final column depends only on initial cells within 18 columns. This lets the decoder test one newly exposed text band at a time while retaining candidate suffixes.

## Solution

The reverse DP starts from the right-edge terminator candidates and stores six-character contexts with predecessor links. For each candidate glyph it renders the local text window, evolves it for 18 B3/S23 generations, and keeps only candidates whose newly exposed band exactly matches the screenshot. A native C++ evaluator made the largest layer practical; 128 decisions per layer were cross-checked against the Python implementation.

The surviving predecessor graph contains one complete 38-character string. The re-runnable script is [solve.py](solve.py); `--rebuild` regenerates the DP from the screenshot and the included DejaVu 2.37 fonts, while the default mode reconstructs from the saved layers. Both modes verify the screenshot-derived grid before printing the flag.

```bash
python3 solve.py --rebuild
```

Verified output:

```text
FortID{R3al_L1f3_H45_N0_R3w1nd_Bu7t0n}
```

The full Pillow render followed by 18 Life generations differs from all 13,752 target cells in zero cells.

## Tools

Python 3.14.7, NumPy 2.5.3, Pillow 12.3.0, and a C++17 compiler for the native band evaluator.

## Lessons

Use locality before trying to invert an irreversible cellular automaton globally. Exact font metrics and source-over alpha compositing matter at the initial raster stage; the full-grid replay is the final check against a plausible-looking but incorrect phrase.

## Flag

```text
FortID{R3al_L1f3_H45_N0_R3w1nd_Bu7t0n}
```

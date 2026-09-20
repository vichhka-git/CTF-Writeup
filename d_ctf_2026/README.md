# D-CTF 2026

Public writeups for solved challenges from DefCamp CTF 2026 Qualifiers.

Only challenges with a solver and writeup are included. Original handouts are kept under `files/`; platform cookies, flags, derived forensic dumps, and local workspaces are intentionally excluded.

| Challenge | Category | Writeup | Solver |
| --- | --- | --- | --- |
| [power-with-errors](challenges/crypto/power-with-errors/) | Crypto | [writeup](challenges/crypto/power-with-errors/writeup.md) | [solve.py](challenges/crypto/power-with-errors/solve.py) |
| [Gnome Breaker](challenges/forensics/Gnome-Breaker/) | Forensics | [writeup](challenges/forensics/Gnome-Breaker/writeup.md) | [solve.py](challenges/forensics/Gnome-Breaker/solve.py) |
| [Kameosa](challenges/forensics/Kameosa/) | Forensics | [writeup](challenges/forensics/Kameosa/writeup.md) | [solve_all.py](challenges/forensics/Kameosa/solve_all.py) |
| [Kanji](challenges/forensics/Kanji/) | Forensics | [writeup](challenges/forensics/Kanji/writeup.md) | [solve.py](challenges/forensics/Kanji/solve.py) |
| [legacy](challenges/misc/legacy/) | Misc | [writeup](challenges/misc/legacy/writeup.md) | [solve.py](challenges/misc/legacy/solve.py) |
| [solstice-9](challenges/misc/solstice-9/) | Misc | [writeup](challenges/misc/solstice-9/writeup.md) | [solve.py](challenges/misc/solstice-9/solve.py) |
| [nephilim - REVENGE](challenges/pwn/nephilim---REVENGE/) | Pwn | [writeup](challenges/pwn/nephilim---REVENGE/writeup.md) | [solve.py](challenges/pwn/nephilim---REVENGE/solve.py) |
| [aiscrimination](challenges/web/aiscrimination/) | Web | [writeup](challenges/web/aiscrimination/writeup.md) | [solve.py](challenges/web/aiscrimination/solve.py) |
| [defcamp-supply](challenges/web/defcamp-supply/) | Web | [writeup](challenges/web/defcamp-supply/writeup.md) | [solve.py](challenges/web/defcamp-supply/solve.py) |

## Split handouts

GitHub blocks regular Git files over 100 MiB. The three large original handouts are stored as numbered pieces of ZIP streams. Reassemble them with `scripts/join-parts.sh` and then extract as described in each directory:

- `forensics/Kameosa/files/toc.7z.zip.001` … `.???` → `toc.7z`
- `forensics/Kanji/files/small.zip.001` … `.???` → the original `small.zip`
- `misc/solstice-9/files/solstice9-firmware.zip.001` … `.???` → `solstice9-firmware.img`

The D-CTF challenge set also contains other solved deployment challenges in the source workspace, but they lacked a finalized writeup or solver pair and were not copied.

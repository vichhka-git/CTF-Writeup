# FortID CTF 2026 Writeup: Hic Sunt Dracones

- **Category:** Crypto
- **Challenge author:** ipaljak
- **Points / Solves:** 116 pts / 166 solves
- **Flag:** `FortID{1f_D0n_Knu7h_H4s_1t_0n_th3_W4ll_Th3n_17_Mu57_B3_G00d_F0r_Crypt0_r1ght?}`

---

## Challenge

> You have been warned... 🐉

---

## Summary

The challenge encodes the flag characters into points using Koblitz encoding ($x = 20m + j$) and draws a Heighway dragon curve starting at each point using a `HeadlessTurtle`. Because turtle heading is never reset between rendered points, the net displacement vector $(dx, dy)$ for each point follows a 4-step periodic pattern where even steps have $dx = 0$, directly preserving the original $x$-coordinates. The odd steps are offset by $\pm 128 \times \text{size}$, which is easily recovered using known plaintext (`FortID{`).

## Solution

### Step 1: Analyze Turtle Motion and Dragon Curve Invariants

In `chall.py`, the flag is converted into elliptic curve points via Koblitz's embedding method, where character $m = \text{ord}(c)$ is encoded as an $x$-coordinate $x_m = 20m + j$ with $1 \le j < 20$. Each point is then transformed by `dragon.dragon_render(point, private_key)`:
- The turtle starts at $(x_m, y_m)$ and turns by `angle` ($0^\circ$ or $180^\circ$).
- The turtle walks the dragon curve instructions for `iterations` (between 10 and 14).
- The turtle heading is maintained across point renderings (never reset to $0^\circ$).

Simulating the heading progression for `iterations = 14, angle = 180` reveals the exact displacement sequence modulo 4:
- $i \equiv 0 \pmod 4$: $dx = 0, dy = 128$
- $i \equiv 1 \pmod 4$: $dx = 128, dy = 0$
- $i \equiv 2 \pmod 4$: $dx = 0, dy = -128$
- $i \equiv 3 \pmod 4$: $dx = -128, dy = 0$

Thus:
- For $i \equiv 0, 2 \pmod 4$, $x_{\text{end}} = x_m$ directly.
- For $i \equiv 1 \pmod 4$, $x_{\text{end}} = x_m + 128 \times \text{size}$.
- For $i \equiv 3 \pmod 4$, $x_{\text{end}} = x_m - 128 \times \text{size}$.

### Step 2: Recover Size and Extract Flag

Using the known plaintext prefix `FortID{`:
- Point 1 is character `'o'` ($m = 111 \implies x_1 = 2220 + j_1$).
- Point 3 is character `'t'` ($m = 116 \implies x_3 = 2320 + j_3$).
- $x_{\text{end}}[1] + x_{\text{end}}[3] = x_1 + x_3 = 4540 + (j_1 + j_3) = 4546$, giving $j_1 + j_3 = 6$.
- Checking $(x_{\text{end}}[1] - (2220 + j_1)) \equiv 0 \pmod{128}$ gives $j_1 = 5, j_3 = 1$ and recovers `size = 278012580452280145225903631781209822295`.
- Inverting the offsets for all points recovers each $x_m$, and dividing by 20 gives each character $m = \lfloor x_m / 20 \rfloor$.

```python
#!/usr/bin/env python3
from pathlib import Path

def character_to_point(output):
    output_x, output_y = output.split('XY')
    x_end = [int(x) for x in output_x.split('X')[1:]]
    y_end = [int(y) for y in output_y.split('Y')[:-1]]
    return list(zip(x_end, y_end))

points = character_to_point(Path("output.txt").read_text().strip())
p1, p3 = points[1][0], points[3][0]
total_j = (p1 + p3) - (2220 + 2320)

for j1 in range(1, 20):
    j3 = total_j - j1
    if 1 <= j3 < 20 and (p1 - (2220 + j1)) % 128 == 0:
        size = (p1 - (2220 + j1)) // 128
        break

flag = []
for i, (px, py) in enumerate(points):
    if i % 4 in (0, 2):
        xi = px
    elif i % 4 == 1:
        xi = px - 128 * size
    else:
        xi = px + 128 * size
    flag.append(chr(xi // 20))

print(''.join(flag))
```

## Flag

```
FortID{1f_D0n_Knu7h_H4s_1t_0n_th3_W4ll_Th3n_17_Mu57_B3_G00d_F0r_Crypt0_r1ght?}
```

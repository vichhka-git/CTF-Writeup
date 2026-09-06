#!/usr/bin/env python3
"""Teto engine v2: exact game simulation + placement AI + write planner."""
from __future__ import annotations
import ctypes

WIDTH, HEIGHT, ROW_BYTES = 10, 20, 2
PATTERNS = {
    0: {0: "####............", 1: ".#...#...#...#..",
        2: "####............", 3: ".#...#...#...#.."},
    1: {r: "##..##.........." for r in range(4)},
    2: {0: ".#..###.........", 1: "#...##..#.......",
        2: "###..#..........", 3: ".#..##...#......"},
    3: {0: ".##.##..........", 1: "#...##...#......",
        2: ".##.##..........", 3: "#...##...#......"},
    4: {0: "##...##.........", 1: ".#..##..#.......",
        2: "##...##.........", 3: ".#..##..#......."},
    5: {0: "#...###.........", 1: "##..#...#.......",
        2: "###...#.........", 3: ".#...#..##......"},
    6: {0: "..#.###.........", 1: "#...#...##......",
        2: "###.#...........", 3: "##...#...#......"},
}
KINDNAME = "IOTSZJL"


def rand_seq(n: int) -> list[int]:
    lib = ctypes.CDLL("libc.so.6")
    lib.srand(1)
    return [lib.rand() % 7 for _ in range(n)]


def cells(kind: int, rot: int) -> list[tuple[int, int]]:
    s = PATTERNS[kind][rot & 3]
    return [(x, y) for y in range(4) for x in range(4) if s[y * 4 + x] == "#"]


def piece_width(kind: int, rot: int) -> int:
    c = cells(kind, rot)
    return (max(x for x, _ in c) + 1) if c else 1


def piece_tall(kind: int, rot: int) -> bool:
    return any(y == 3 for _, y in cells(kind, rot))


def spawn_x(kind: int) -> int:
    return max(WIDTH // 2 - piece_width(kind, 0) // 2, 0)


class Game:
    """Mirrors teto.c: 10x20 visible board, width/height fields, ceiling_pressure."""

    def __init__(self) -> None:
        self.g = [[0] * WIDTH for _ in range(HEIGHT)]
        self.width = WIDTH
        self.pressure = 0
        self.writes: list[tuple[int, int]] = []   # (stage_idx, bit) OR-writes above board

    # --- exact C helpers -------------------------------------------------
    def stage_cell(self, x: int, y: int) -> int:
        if x < 0 or x >= WIDTH or y < 0 or y >= HEIGHT:
            return 0
        return self.g[y][x]

    def collides(self, kind: int, rot: int, nx: int, ny: int) -> bool:
        for xx, yy in cells(kind, rot):
            x, y = nx + xx, ny + yy
            if x < 0:
                return True
            if y < 0:
                if x >= self.width:
                    return True
            elif x >= WIDTH:
                return True
            if y >= HEIGHT:
                return True
            if y >= 0 and self.stage_cell(x, y):
                return True
        return False

    def top_pressure(self) -> int:
        if sum(sum(r) for r in self.g) >= 60:
            self.pressure = 1
        return self.pressure

    def set_cell(self, x: int, y: int) -> None:
        if x < 0 or y < -1 or x >= self.width or y >= HEIGHT:
            return
        idx = y * ROW_BYTES + (x >> 3)
        if 0 <= idx < HEIGHT * ROW_BYTES:
            if y >= 0 and x < WIDTH:
                self.g[y][x] = 1
            elif y >= 0:
                pass  # x in [10,15] -> stage byte inside board area, invisible
        else:
            if idx == -2:
                self.width |= 1 << (x & 7)
            elif idx == -1:
                self.width |= 1 << (8 + (x & 7))
            else:
                self.writes.append((idx, x & 7))

    def lock(self, kind: int, rot: int, px: int, py: int) -> None:
        for xx, yy in cells(kind, rot):
            self.set_cell(px + xx, py + yy)

    def row_full(self, y: int) -> bool:
        return all(self.g[y][x] for x in range(WIDTH))

    def clear_lines(self) -> int:
        n = 0
        y = 0
        while y < HEIGHT:
            if self.row_full(y):
                # clear_row: rows 0..y-1 shift to 1..y, row 0 zeroed (stride 2)
                self.g = [[0] * WIDTH] + self.g[:y] + self.g[y + 1:]
                n += 1
            y += 1
        return n

    def occupied(self) -> int:
        return sum(sum(r) for r in self.g)

    def heights(self) -> list[int]:
        h = [0] * WIDTH
        for x in range(WIDTH):
            for y in range(HEIGHT):
                if self.g[y][x]:
                    h[x] = HEIGHT - y
                    break
        return h

    # --- key-level actions ----------------------------------------------
    def rotate_at_spawn(self, kind: int, rot: int, px: int, py: int):
        """Replicate rotate_piece; returns (nx, ny, nrot, lock?) or None if blocked."""
        nr = (rot + 1) & 3
        kicks = [(0, 0), (-1, 0), (1, 0), (0, -1), (-1, -1), (1, -1)]
        entry = py < 0 and piece_tall(kind, nr) and self.top_pressure()
        table = [(0, -2), (-1, -2), (1, -2), (0, 0), (-1, 0), (1, 0)] if entry else kicks
        for dx, dy in table:
            nx, ny = px + dx, py + dy
            if self.collides(kind, nr, nx, ny):
                continue
            return nx, ny, nr, bool(entry and dy < 0)
        return None

    def hard_drop(self, kind: int, rot: int, px: int, py: int):
        if self.collides(kind, rot, px, py):
            return None
        while py + 1 < HEIGHT and not self.collides(kind, rot, px, py + 1):
            py += 1
        if py < 0:
            return None
        return py


def keys_place(kind: int, rot: int, px: int) -> str:
    sx = spawn_x(kind)
    return "w" * rot + ("a" * (sx - px) if px < sx else "d" * (px - sx)) + " "


def keys_write(write_x: int) -> str:
    px = write_x - 1
    sx = 3  # I spawn x
    return ("d" * (px - sx) if px >= sx else "a" * (sx - px)) + "w"



def _metrics(g, kind, rot, px, py, cleared, piece_cells_cleared):
    b = g.g
    # row transitions (walls count as filled)
    rowt = 0
    for y in range(HEIGHT):
        prev = 1
        for x in range(WIDTH):
            c = b[y][x]
            if c != prev:
                rowt += 1
            prev = c
        if prev != 1:
            rowt += 1
    # column transitions (bottom filled, top empty)
    colt = 0
    for x in range(WIDTH):
        prev = 0
        for y in range(HEIGHT):
            c = b[y][x]
            if c != prev:
                colt += 1
            prev = c
        if prev != 1:
            colt += 1
    holes = 0
    for x in range(WIDTH):
        seen = False
        for y in range(HEIGHT):
            if b[y][x]:
                seen = True
            elif seen:
                holes += 1
    h = g.heights()
    wells = 0
    for x in range(WIDTH):
        for y in range(HEIGHT):
            if b[y][x]:
                continue
            left = b[y][x - 1] if x > 0 else 1
            right = b[y][x + 1] if x < WIDTH - 1 else 1
            if left and right:
                d = 1
                yy = y + 1
                while yy < HEIGHT and not b[yy][x]:
                    d += 1
                    yy += 1
                wells += d * (d + 1) // 2
                break
    landing = HEIGHT - py
    eroded = cleared * piece_cells_cleared
    return (-4.500158825082766 * landing
            + 3.4181268101392694 * eroded
            - 3.2178882868487753 * rowt
            - 9.348695305445199 * colt
            - 7.899265427351652 * holes
            - 3.3855972247263626 * wells)


def evaluate(g: Game) -> tuple:
    h = g.heights()
    holes = 0
    for x in range(WIDTH):
        seen = False
        for y in range(HEIGHT):
            if g.g[y][x]:
                seen = True
            elif seen:
                holes += 1
    agg = sum(h)
    bump = sum(abs(h[i] - h[i + 1]) for i in range(WIDTH - 1))
    return holes, agg, bump, max(h) if h else 0


def choose(game: Game, kind: int, allow_clear: bool, mode: str = "flat") -> tuple[int, int, int]:
    """Return (rot, px, py) for the best legal placement."""
    rots = [0] if kind in (0, 1) else [0, 1, 2, 3]
    if kind == 0:
        rots = [0]           # never rotate I at spawn: MOVE_LOCK hazard
    best = None
    for rot in rots:
        # verify rotation path is a no-op kick chain from spawn
        px0, py0 = spawn_x(kind), -2
        cx, cy, cr = px0, py0, 0
        ok = True
        for _ in range(rot):
            r = game.rotate_at_spawn(kind, cr, cx, cy)
            if r is None or r[3]:
                ok = False
                break
            cx, cy, cr = r[0], r[1], r[2]
        if not ok or cr != rot or (cx, cy) != (px0, py0):
            continue
        for px in range(-2, WIDTH + 1):
            if game.collides(kind, rot, px, -2):
                continue
            # horizontal reachability from spawn at y = -2
            step = 1 if px > px0 else -1
            reach = True
            q = px0
            while q != px:
                q += step
                if game.collides(kind, rot, q, -2):
                    reach = False
                    break
            if not reach:
                continue
            py = game.hard_drop(kind, rot, px, -2)
            if py is None:
                continue
            trial = Game()
            trial.g = [r[:] for r in game.g]
            trial.width = game.width
            trial.pressure = game.pressure
            trial.lock(kind, rot, px, py)
            full = [y for y in range(HEIGHT) if trial.row_full(y)]
            if full and not allow_clear:
                continue
            pc = sum(1 for xx, yy in cells(kind, rot) if (py + yy) in full)
            ncl = len(full)
            trial.clear_lines()
            sc = _metrics(trial, kind, rot, px, py, ncl, pc)
            if mode == "keep":
                sc -= 6.0 * max(trial.heights()[2:8])
            if best is None or sc > best[0]:
                best = (sc, rot, px, py)
    if best is None:
        return None
    return best[1], best[2], best[3]

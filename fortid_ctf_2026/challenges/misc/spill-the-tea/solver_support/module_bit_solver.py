#!/usr/bin/env python3
"""Expand QR RS checks to GF(2), keeping readable bits in partial symbols."""
from __future__ import annotations
from pathlib import Path as _Path
def _self_dir():
    return _Path(__file__).resolve().parent

import argparse
import sys

import numpy as np
from qrcode import constants

sys.path.insert(0, str(_self_dir()))
import linear_erasure_sweep as le
import qr_decode as qd
from surplus_solver import parse_payload


def solve_gf2(matrix: list[int], rhs: list[int], nvars: int):
    """Solve binary equations with Python-int row bitsets; return x,rank/nullity."""
    rows = [a | (int(b) << nvars) for a, b in zip(matrix, rhs)]
    nrows = len(rows)
    pivots = []
    rank = 0
    for col in range(nvars):
        pivot = next((r for r in range(rank, nrows) if (rows[r] >> col) & 1), None)
        if pivot is None:
            continue
        rows[rank], rows[pivot] = rows[pivot], rows[rank]
        pivot_row = rows[rank]
        for r in range(nrows):
            if r != rank and ((rows[r] >> col) & 1):
                rows[r] ^= pivot_row
        pivots.append(col)
        rank += 1
    coeff_mask = (1 << nvars) - 1
    if any((row & coeff_mask) == 0 and ((row >> nvars) & 1) for row in rows):
        return None, rank, nvars - rank
    x = 0
    for r, col in enumerate(pivots):
        if (rows[r] >> nvars) & 1:
            x |= 1 << col
    return x, rank, nvars - rank


def make_bit_system(base: np.ndarray, unknown: list[tuple[int, int]], h: np.ndarray):
    syn = le.syndrome(base, h)
    rhs = []
    for value in syn:
        rhs.extend((int(value) >> shift) & 1 for shift in range(7, -1, -1))
    rows = [0] * (8 * h.shape[0])
    for col, (pos, bit_index) in enumerate(unknown):
        bit_value = 1 << (7 - bit_index)
        for r in range(h.shape[0]):
            product = int(le.MUL[int(h[r, pos]), bit_value])
            for out_bit in range(8):
                if (product >> (7 - out_bit)) & 1:
                    rows[8 * r + out_bit] |= 1 << col
    return rows, rhs


def bit_blocks(unmasked: np.ndarray, module_support: np.ndarray, mapping, specs,
               local_constraints, threshold: float):
    tx = [int("".join(map(str, unmasked[i:i+8])), 2)
          for i in range(0, 1376, 8)]
    bases = [np.zeros(s.total_count, dtype=np.uint8) for s in specs]
    unknown = [[] for _ in specs]
    for ti, (b, j) in enumerate(mapping):
        value = tx[ti]
        fixed = local_constraints[b].get(j)
        for k in range(8):
            bitmask = 1 << (7-k)
            bit_i = ti * 8 + k
            if fixed and fixed[0] & bitmask:
                if fixed[1] & bitmask:
                    value |= bitmask
                else:
                    value &= ~bitmask
            elif module_support[bit_i] < threshold:
                value &= ~bitmask
                unknown[b].append((j, k))
        bases[b][j] = value
    return bases, unknown


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="pixel_likelihood.npz")
    ap.add_argument("--threshold", type=float, default=.50)
    ap.add_argument("--count", type=int, default=70)
    ap.add_argument("--level", default="Q", choices=("L", "M", "Q", "H", "all"))
    ap.add_argument("--masks", default="0,1,2,3,4,5,6,7")
    args = ap.parse_args()
    model = np.load(str(_self_dir() / args.model))
    bits = model["bits"][:1376].astype(np.uint8)
    support = model["support"][:1376]
    coords = qd.data_coords(qd.function_map())
    levels = [(constants.ERROR_CORRECT_L, "L"),
              (constants.ERROR_CORRECT_M, "M"),
              (constants.ERROR_CORRECT_Q, "Q"),
              (constants.ERROR_CORRECT_H, "H")]
    if args.level != "all":
        levels = [x for x in levels if x[1] == args.level]
    masks = [int(x) for x in args.masks.split(",")]
    candidates = []
    for ec, name in levels:
        specs, mapping = qd.block_layout(ec)
        capacity = sum(s.data_count for s in specs)
        if 12 + args.count * 8 > capacity * 8:
            print("SKIP", name, "capacity", capacity, "count", args.count)
            continue
        local = le.local_constraints(args.count, specs)
        # QR byte-mode terminator ends on a byte boundary here; the remaining
        # data codewords are the standard alternating EC/11 pad sequence.
        end = 12 + 8 * args.count
        pad_start = (end + 4 + 7) // 8
        starts = np.cumsum([0] + [s.data_count for s in specs[:-1]]).tolist()
        for global_i in range(pad_start, capacity):
            value = 0xEC if (global_i - pad_start) % 2 == 0 else 0x11
            for b, spec in enumerate(specs):
                if starts[b] <= global_i < starts[b] + spec.data_count:
                    local[b][global_i - starts[b]] = (0xFF, value)
                    break
        hs = [le.parity_matrix(s.total_count, s.total_count-s.data_count) for s in specs]
        print("LEVEL", name, "parity rows/block", 8 * hs[0].shape[0], flush=True)
        for mask in masks:
            unmasked = np.asarray([bits[i] ^ int(qd.mask_bit(mask, *coords[i]))
                                   for i in range(1376)], dtype=np.uint8)
            bases, unknown = bit_blocks(unmasked, support, mapping, specs, local,
                                        args.threshold)
            codes = []
            summaries = []
            for b in range(len(specs)):
                u = unknown[b]
                rows, rhs = make_bit_system(bases[b], u, hs[b])
                solution, rank, nullity = solve_gf2(rows, rhs, len(u))
                summaries.append((len(u), rank, nullity, solution is not None))
                if solution is None or nullity:
                    codes.append(None)
                    continue
                code = bases[b].copy()
                for col, (pos, bit_index) in enumerate(u):
                    if (solution >> col) & 1:
                        code[pos] |= 1 << (7-bit_index)
                if le.syndrome(code, hs[b]).any():
                    raise AssertionError("binary solution does not satisfy RS parity")
                if any((int(code[j]) & bitmask) != (value & bitmask)
                       for j, (bitmask, value) in local[b].items()):
                    raise AssertionError("known plaintext was not preserved")
                codes.append(code)
            print("MASK", mask, "vars/rank/free/consistent", summaries, flush=True)
            if all(x is not None for x in codes):
                data = b"".join(bytes(c[:s.data_count]) for c, s in zip(codes, specs))
                payload = parse_payload(data, args.count)
                print("DATA", name, mask, "payload", repr(payload),
                      "datahex", data.hex(), flush=True)
                if payload:
                    candidates.append((name, mask, args.count, payload, data, codes))
    print("CANDIDATE_COUNT", len(candidates), flush=True)
    for x in candidates:
        print("FLAG", x[:4], "datahex", x[4].hex(), flush=True)


if __name__ == "__main__":
    main()
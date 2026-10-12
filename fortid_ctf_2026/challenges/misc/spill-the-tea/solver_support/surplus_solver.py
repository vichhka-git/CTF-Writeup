#!/usr/bin/env python3
"""Solve the candidate Q/mask-3 QR using low-support erasures and parity slack."""
from __future__ import annotations
from pathlib import Path as _Path
def _self_dir():
    return _Path(__file__).resolve().parent

import itertools
import sys

import numpy as np
from qrcode import constants

sys.path.insert(0, str(_self_dir()))
import linear_erasure_sweep as le
import qr_decode as qd


def solve_affine(a: np.ndarray, b: np.ndarray):
    """Return x0, nullspace basis, rank for A*x=b over GF(256), or None."""
    a = np.concatenate((a.copy(), b[:, None].copy()), axis=1)
    rows, cols = a.shape[0], a.shape[1] - 1
    pivot_cols = []
    rank = 0
    for col in range(cols):
        found = np.flatnonzero(a[rank:, col])
        if not len(found):
            continue
        pivot = rank + int(found[0])
        if pivot != rank:
            a[[rank, pivot]] = a[[pivot, rank]]
        val = int(a[rank, col])
        inv = int(le.EXP[255 - int(le.LOG[val])])
        a[rank, col:] = le.MUL[a[rank, col:], inv]
        factors = a[:, col].copy()
        factors[rank] = 0
        nz = np.flatnonzero(factors)
        if len(nz):
            a[nz, col:] ^= le.MUL[factors[nz, None], a[rank, col:][None, :]]
        pivot_cols.append(col)
        rank += 1
        if rank == rows:
            break
    if np.any((a[:, :cols] == 0).all(axis=1) & (a[:, cols] != 0)):
        return None
    free_cols = [j for j in range(cols) if j not in pivot_cols]
    x0 = np.zeros(cols, dtype=np.uint8)
    for row, col in enumerate(pivot_cols):
        x0[col] = a[row, cols]
    basis = []
    for free in free_cols:
        v = np.zeros(cols, dtype=np.uint8)
        v[free] = 1
        for row, col in enumerate(pivot_cols):
            v[col] = a[row, free]
        basis.append(v)
    return x0, basis, rank


def apply_deltas(base: np.ndarray, positions: list[int], delta: np.ndarray):
    out = base.copy()
    out[positions] ^= delta
    return out


def partial_fills(local: dict[int, tuple[int, int]]):
    partial = [(j, mask, value) for j, (mask, value) in local.items() if mask != 0xFF]
    domains = []
    for j, mask, value in partial:
        free = [bit for bit in range(8) if not mask & (1 << bit)]
        choices = []
        for n in range(1 << len(free)):
            x = value & mask
            for k, bit in enumerate(free):
                if (n >> k) & 1:
                    x |= 1 << bit
            choices.append(x)
        domains.append((j, choices))
    for values in itertools.product(*(v for _, v in domains)) if domains else [()]:
        yield {domains[i][0]: values[i] for i in range(len(domains))}


def constrained_overdetermined(received, erased, local, h):
    """Enumerate partial plaintext bytes and require all parity rows to agree."""
    full = {j: value for j, (mask, value) in local.items() if mask == 0xFF}
    output = []
    for partial in partial_fills(local):
        fixed = {**full, **partial}
        base = received.copy()
        for j, value in fixed.items():
            base[j] = value
        unknown = sorted(set(erased) - set(fixed))
        delta = le.solve_delta(base, unknown, h)
        if delta is None:
            continue
        corrected = apply_deltas(base, unknown, delta)
        if le.syndrome(corrected, h).any():
            raise AssertionError("solver returned a non-codeword")
        if any((int(corrected[j]) & mask) != (value & mask)
               for j, (mask, value) in local.items()):
            continue
        output.append((corrected, len(unknown), len(erased) - len(unknown)))
    return output


def parse_payload(data: bytes, count=70):
    bits = "".join(f"{x:08b}" for x in data)
    if len(bits) < 12 + count * 8:
        return None
    if int(bits[:4], 2) != 4 or int(bits[4:12], 2) != count:
        return None
    payload = bytes(int(bits[i:i+8], 2) for i in range(12, 12 + count * 8, 8))
    if not payload.startswith(b"FortID{") or not payload.endswith(b"}"):
        return None
    if any(c not in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
           for c in payload[7:-1]):
        return None
    return payload


def main():
    model = np.load(str(_self_dir() / "pixel_likelihood.npz"))
    bits = model["bits"].astype(np.uint8)
    support = model["support"]
    coords = qd.data_coords(qd.function_map())
    ec = constants.ERROR_CORRECT_Q
    specs, mapping = qd.block_layout(ec)
    mask = 3
    raw = np.asarray([bits[i] ^ int(qd.mask_bit(mask, *coords[i]))
                      for i in range(1376)], dtype=np.uint8)
    tx = np.asarray([int("".join(map(str, raw[i:i+8])), 2)
                     for i in range(0, 1376, 8)], dtype=np.uint8)
    rx = [np.zeros(s.total_count, dtype=np.uint8) for s in specs]
    erased = [set() for _ in specs]
    for ti, (b, j) in enumerate(mapping):
        rx[b][j] = tx[ti]
        if np.any(support[ti*8:ti*8+8] < .30):
            erased[b].add(j)
    h = [le.parity_matrix(s.total_count, s.total_count-s.data_count) for s in specs]
    local = le.local_constraints(70, specs)

    print("candidate=Q mask=3 count=70; support<.30", flush=True)
    survivors = {}
    for b in (0, 1, 3):
        e = sorted(erased[b])
        overlap = sorted(set(e) & set(local[b]))
        unknown_if_fixed = len(set(e) - set(local[b]))
        print(f"block {b}: erasures={len(e)} parity={h[b].shape[0]} "
              f"surplus={h[b].shape[0]-len(e)} known={local[b]} "
              f"erasure_known_overlap={overlap} unknown_after_plaintext={unknown_if_fixed}",
              flush=True)
        got = constrained_overdetermined(rx[b], e, local[b], h[b])
        print(f"block {b}: authenticated_solutions={len(got)}", flush=True)
        for ix, (code, unknown_n, fixed_n) in enumerate(got):
            print(f"  solution {ix}: unknowns={unknown_n}, fixed_erasure_symbols={fixed_n}, "
                  f"data={bytes(code[:specs[b].data_count])!r}, "
                  f"data_hex={bytes(code[:specs[b].data_count]).hex()}", flush=True)
        survivors[b] = [x[0] for x in got]
    if any(not survivors[b] for b in (0, 1, 3)):
        print("VERDICT: at least one surplus-check block has no solution", flush=True)
        return

    b = 2
    e = sorted(erased[b])
    base = rx[b].copy()
    synd = le.syndrome(base, h[b])
    mat = h[b][:, e].copy()
    affine = solve_affine(mat, synd)
    if affine is None:
        print("block 2: inconsistent despite being underdetermined", flush=True)
        return
    particular, basis, rank = affine
    print(f"block 2: erasures={len(e)} parity={h[b].shape[0]} rank={rank} "
          f"nullity={len(basis)} free_positions={[e[i] for i in range(len(e)-len(basis), len(e))] if basis else []}",
          flush=True)
    if len(basis) != 2:
        print("unexpected block-2 nullity; stop without guessing", flush=True)
        return
    block2_candidates = []
    # The two free values are RS correction deltas and may be parity symbols,
    # so enumerate all GF(256)^2 assignments; framing filters the data bytes.
    for x in range(256):
        d0 = le.MUL[basis[0], x]
        for y in range(256):
            delta = particular ^ d0 ^ le.MUL[basis[1], y]
            corrected = apply_deltas(base, e, delta)
            if le.syndrome(corrected, h[b]).any():
                raise AssertionError("affine nullspace candidate failed parity")
            block2_candidates.append(corrected)
    print("block 2: enumerated", len(block2_candidates), "solutions", flush=True)

    framed = []
    combinations = 0
    for c0 in survivors[0]:
      for c1 in survivors[1]:
       for c3 in survivors[3]:
        for c2 in block2_candidates:
            combinations += 1
            data = b"".join(bytes(c[:s.data_count])
                             for c, s in zip((c0, c1, c2, c3), specs))
            payload = parse_payload(data)
            if payload:
                framed.append((payload, data, (c0, c1, c2, c3)))
    print(f"combined={combinations} framed_candidates={len(framed)}", flush=True)
    for payload, data, codewords in framed:
        print("CANDIDATE", repr(payload), "data_hex", data.hex(), flush=True)
    if not framed:
        print("VERDICT: surplus checks or flag-character filter rejected all candidates", flush=True)


if __name__ == "__main__":
    main()
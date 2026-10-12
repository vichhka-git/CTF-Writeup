#!/usr/bin/env python3
"""Rank uncertain individual modules and solve expanded binary RS equations."""
from __future__ import annotations
from pathlib import Path as _Path
def _self_dir():
    return _Path(__file__).resolve().parent

import argparse
import itertools
import sys

import numpy as np
from qrcode import constants

sys.path.insert(0, str(_self_dir()))
import linear_erasure_sweep as le
import qr_decode as qd
from module_bit_solver import make_bit_system, solve_gf2
from surplus_solver import parse_payload


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="pixel_likelihood.npz")
    ap.add_argument("--level", default="Q", choices=("L", "M", "Q", "H"))
    ap.add_argument("--masks", default="3")
    ap.add_argument("--count", type=int, default=70)
    ap.add_argument("--base-threshold", type=float, default=.30)
    ap.add_argument("--max-vars", type=int, default=191)
    ap.add_argument("--rank", choices=("product", "support", "llr"), default="product")
    ap.add_argument("--known-body", default="",
                    help="optional verified/investigated chars as START:TEXT, e.g. 29:W")
    args = ap.parse_args()

    model = np.load(str(_self_dir() / args.model))
    bits = model["bits"][:1376].astype(np.uint8)
    support = model["support"][:1376]
    llr = model["llr"][:1376]
    confidence = {"product": support*llr, "support": support, "llr": llr}[args.rank]
    coords = qd.data_coords(qd.function_map())
    ec = {"L":constants.ERROR_CORRECT_L,"M":constants.ERROR_CORRECT_M,
          "Q":constants.ERROR_CORRECT_Q,"H":constants.ERROR_CORRECT_H}[args.level]
    specs, mapping = qd.block_layout(ec)
    local = le.local_constraints(args.count, specs)
    if args.known_body:
        start_text, text = args.known_body.split(":", 1)
        body_start = int(start_text)
        block_starts = np.cumsum([0] + [s.data_count for s in specs[:-1]]).tolist()
        for ci, ch in enumerate(text):
            source_bit = 12 + 8 * (7 + body_start + ci)
            for k, bit_char in enumerate(f"{ord(ch):08b}"):
                global_bit = source_bit + k
                global_byte, shift = divmod(global_bit, 8)
                for b, spec in enumerate(specs):
                    if block_starts[b] <= global_byte < block_starts[b] + spec.data_count:
                        j = global_byte - block_starts[b]
                        bitmask = 1 << (7-shift)
                        old_mask, old_value = local[b].get(j, (0, 0))
                        if old_mask & bitmask and bool(old_value & bitmask) != (bit_char == "1"):
                            raise SystemExit("known body text conflicts with framing constraints")
                        local[b][j] = (old_mask | bitmask,
                                       old_value | (bitmask if bit_char == "1" else 0))
                        break
    hs = [le.parity_matrix(s.total_count, s.total_count-s.data_count) for s in specs]
    if any(args.max_vars > 8*h.shape[0] for h in hs):
        raise SystemExit("max-vars cannot exceed the binary parity equations")

    # For each deinterleaved block, get the baseline unknown bits from cells
    # below the support threshold, then append least-confident visible modules.
    block_bits = [[] for _ in specs]
    for ti, (b, j) in enumerate(mapping):
        for k in range(8):
            bit_i = ti*8+k
            bitmask = 1 << (7-k)
            fixed = local[b].get(j)
            if fixed and (fixed[0] & bitmask):
                continue
            block_bits[b].append((float(confidence[bit_i]), bit_i, j, k,
                                  bool(support[bit_i] < args.base_threshold)))

    # The masks change the hard observation, but not the binary parity matrix
    # or which module coordinates are selected for each quota.
    candidates_by_mask = {}
    for b, spec in enumerate(specs):
        block_bits[b].sort(key=lambda x: (x[0], x[1]))
    for mask in [int(x) for x in args.masks.split(",")]:
      unmasked = np.asarray([bits[i] ^ int(qd.mask_bit(mask, *coords[i]))
                             for i in range(1376)], dtype=np.uint8)
      tx = [int("".join(map(str, unmasked[i:i+8])), 2)
            for i in range(0, 1376, 8)]
      rx = [np.zeros(s.total_count, dtype=np.uint8) for s in specs]
      for ti, (b, j) in enumerate(mapping): rx[b][j] = tx[ti]

      per_block = []
      for b, spec in enumerate(specs):
        fixed = local[b]
        original = rx[b].copy()
        for j, (bitmask, value) in fixed.items():
            original[j] = (int(original[j]) & (0xff ^ bitmask)) | (value & bitmask)
        base_items = [x for x in block_bits[b] if x[4]]
        ranked_items = [x for x in block_bits[b] if not x[4]]
        # Rebuild the baseline so uncertain positions are zero and plaintext
        # bits are exact. Additional variables are appended in confidence order.
        choices = {}
        base_unknown = [(x[2], x[3]) for x in base_items]
        for q in range(len(base_unknown), args.max_vars + 1):
            extra_n = q-len(base_unknown)
            if extra_n > len(ranked_items):
                break
            selected = base_items + ranked_items[:extra_n]
            unknown = [(x[2], x[3]) for x in selected]
            base = original.copy()
            for pos, bit_index in unknown:
                base[pos] = int(base[pos]) & (0xff ^ (1 << (7-bit_index)))
            mat, rhs = make_bit_system(base, unknown, hs[b])
            solution, rank, nullity = solve_gf2(mat, rhs, len(unknown))
            if solution is None or nullity:
                continue
            code = base.copy()
            for col, (pos, bit_index) in enumerate(unknown):
                if (solution >> col) & 1:
                    code[pos] |= 1 << (7-bit_index)
            if le.syndrome(code, hs[b]).any():
                raise AssertionError("binary candidate violates QR RS parity")
            if any((int(code[j]) & m) != (v & m) for j,(m,v) in fixed.items()):
                raise AssertionError("candidate violates known plaintext")
            key = bytes(code)
            choices.setdefault(key, (code, q, 8*hs[b].shape[0]-q))
        vals = list(choices.values())
        print(f"block {b}: baseline_bits={len(base_unknown)} "
              f"ranked_solutions={len(vals)}", flush=True)
        for code, q, slack in vals:
            print(f"  vars={q} surplus_bits={slack} data={bytes(code[:spec.data_count]).hex()}",
                  flush=True)
        per_block.append(vals)
      counts = [len(x) for x in per_block]
      print("mask",mask,"candidate_counts",counts,flush=True)
      if all(counts):
        for combo in itertools.product(*per_block):
            data = b"".join(bytes(x[0][:s.data_count])
                             for x,s in zip(combo,specs))
            payload = parse_payload(data,args.count)
            if payload:
                print("FLAG-CANDIDATE",repr(payload),
                      "variables",[x[1] for x in combo],
                      "surplus_bits",[x[2] for x in combo],flush=True)
                candidates_by_mask[mask]=payload
    print("CANDIDATES",candidates_by_mask,flush=True)


if __name__ == "__main__":
    main()
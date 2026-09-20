"""Recover noisy matrix-power masks using SageMath and flatter.

Run: python3 solve.py --root /path/to/power-with-errors
All output artifacts go to --out (default: a new directory under agent_workspace).
"""
import argparse
import ast
import json
import time
from pathlib import Path

from sage.all import GF, ZZ, matrix

from recover_last import recover_last, reduce_basis
from verify import verify


def recover_pair(raw, p, n):
    field = GF(p)
    size = n * n
    unknowns = 2 * (size - 1)
    dim = size + unknowns + 1
    center = matrix(ZZ, n, [0] + [127] * (size - 1))
    u, v = [matrix(ZZ, n, values) - center for values in raw[:2]]
    basis = matrix(ZZ, dim)
    for i in range(size):
        basis[i, i] = p
    for j in range(unknowns):
        index = j % (size - 1) + 1
        unit = matrix(ZZ, n)
        unit[index // n, index % n] = 1
        column = unit * v - v * unit if j < size - 1 else u * unit - unit * u
        for i, value in enumerate(column.list()):
            basis[size + j, i] = value % p
        basis[size + j, size + j] = 512
    for i, value in enumerate((u * v - v * u).list()):
        basis[-1, i] = -value % p
    basis[-1, -1] = 65536
    reduced = reduce_basis(basis, timeout=600, cap_threads=False)
    for row in reduced.rows():
        if abs(row[-1]) != 65536:
            continue
        sign = 1 if row[-1] > 0 else -1
        scaled = row[size:-1]
        if any(value % 512 for value in scaled):
            continue
        values = [int(sign * value // 512) + 127 for value in scaled]
        if not all(0 <= value <= 255 for value in values):
            continue
        keys = [[0] + values[:size - 1], [0] + values[size - 1:]]
        clean = [matrix(field, n, r) - matrix(field, n, k)
                 for r, k in zip(raw[:2], keys)]
        if clean[0] * clean[1] == clean[1] * clean[0]:
            return keys
    raise RuntimeError("No verified byte-valued mask pair found")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--first-pair", type=Path, help="Optional verified probe artifact for group zero")
    args = parser.parse_args()
    out = args.out or args.root / "agent_workspace" / ("recovery-%d" % time.time_ns())
    out.mkdir(parents=True, exist_ok=True)
    params = dict(line.split("=", 1) for line in (args.root / "params").read_text().splitlines())
    p, n, groups = (int(params[k]) for k in ("p", "n", "t"))
    field = GF(p)
    keys = []
    started = time.monotonic()
    for group in range(groups):
        raw = ast.literal_eval((args.root / f"testcase_{group}.in").read_text())
        print(f"Recovering group {group}...", flush=True)
        pair = (json.loads(args.first_pair.read_text())["masks"]
                if group == 0 and args.first_pair else recover_pair(raw, p, n))
        clean = matrix(field, n, raw[0]) - matrix(field, n, pair[0])
        other = matrix(field, n, raw[1]) - matrix(field, n, pair[1])
        assert clean * other == other * clean
        third = recover_last(clean, matrix(field, n, raw[2]))
        keys.append(pair + [third])
        (out / f"group{group}-masks.json").write_text(json.dumps(keys[-1]))
        print(f"Recovered group {group}: three masks; elapsed {time.monotonic() - started:.2f}s", flush=True)
    (out / "all_masks.json").write_text(json.dumps(keys))
    plaintext = verify(args.root, keys)
    (out / "plaintext.bin").write_bytes(plaintext)
    print(f"padded_plaintext={plaintext!r}", flush=True)
    print(plaintext.rstrip(b"\0").decode("ascii"), flush=True)
    print(f"Artifacts: {out}", flush=True)


if __name__ == "__main__":
    main()

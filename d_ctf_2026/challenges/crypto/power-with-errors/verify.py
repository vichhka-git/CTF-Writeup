"""Verify recovered masks against all supplied matrix groups, then decrypt."""
import argparse
import ast
import json
from pathlib import Path

from sage.all import GF, identity_matrix, matrix, vector


def verify(root, keys):
    params = dict(line.split("=", 1) for line in (root / "params").read_text().splitlines())
    p, n, t, c = (int(params[name]) for name in ("p", "n", "t", "c"))
    field = GF(p)
    assert len(keys) == t
    plaintext = bytearray((root / "enc").read_bytes())
    assert len(plaintext) == n * n
    for group, group_keys in enumerate(keys):
        samples = ast.literal_eval((root / f"testcase_{group}.in").read_text())
        assert len(samples) == len(group_keys) == c
        corrected = []
        for sample, key in zip(samples, group_keys):
            assert len(sample) == len(key) == n * n
            assert key[0] == 0 and all(type(x) is int and 0 <= x <= 255 for x in key)
            corrected.append(matrix(field, n, [x - e for x, e in zip(sample, key)]))
            for i, value in enumerate(key):
                plaintext[i] ^= value
        for a in range(c):
            for b in range(a):
                assert corrected[a] * corrected[b] == corrected[b] * corrected[a]
        powers = [identity_matrix(field, n)]
        for _ in range(1, n):
            powers.append(powers[-1] * corrected[0])
        algebra = matrix(field, [power.list() for power in powers]).transpose()
        rank = algebra.rank()
        for sample in corrected[1:]:
            coefficients = algebra.solve_right(vector(field, sample.list()))
            assert algebra * coefficients == vector(field, sample.list())
        print(f"group {group}: byte bounds, fixed zero, all commutators, common algebra checked (rank {rank})", flush=True)
    return bytes(plaintext)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("keys", type=Path)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args()
    result = verify(args.root, json.loads(args.keys.read_text()))
    print(f"padded_plaintext={result!r}")
    print(result.rstrip(b"\0").decode("ascii"))

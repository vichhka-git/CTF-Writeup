"""Recover a byte error mask using one already corrected commuting matrix."""
import os
import re
import subprocess

from sage.all import ZZ, matrix, vector


def reduce_basis(basis, timeout=180, cap_threads=True):
    serialized = "[" + "\n".join("[" + " ".join(map(str, row)) + "]" for row in basis.rows()) + "]"
    env = dict(os.environ)
    if cap_threads:
        env.update(OMP_NUM_THREADS="1", OPENBLAS_NUM_THREADS="1")
    result = subprocess.run(["flatter"], input=serialized, text=True,
                            capture_output=True, check=True, timeout=timeout, env=env)
    values = list(map(int, re.findall(r"-?\d+", result.stdout)))
    assert len(values) == basis.nrows() * basis.ncols()
    return matrix(ZZ, basis.nrows(), basis.ncols(), values)


def recover_last(clean, noisy):
    field = clean.base_ring()
    p, n = int(field.characteristic()), clean.nrows()
    indices = list(range(1, n * n))
    cols = []
    for index in indices:
        unit = matrix(field, n)
        unit[index // n, index % n] = 1
        cols.append((clean * unit - unit * clean).list())
    coefficients = matrix(field, cols).transpose()
    rhs = vector(field, (clean * noisy - noisy * clean).list())
    particular = coefficients.solve_right(rhs)
    kernel = coefficients.right_kernel().basis_matrix().echelon_form()
    pivots = list(kernel.pivots())
    nonpivots = [i for i in range(len(indices)) if i not in pivots]
    rows = [list(map(int, row)) for row in kernel.rows()]
    for index in nonpivots:
        row = [0] * len(indices)
        row[index] = p
        rows.append(row)
    # The affine coset contains the actual mask; its other representatives are huge.
    basis = matrix(ZZ, [row + [0] for row in rows] + [list(map(int, particular)) + [256]])
    reduced = reduce_basis(basis)
    for row in reduced.rows():
        if abs(row[-1]) != 256:
            continue
        sign = 1 if row[-1] == 256 else -1
        key = [0] + [int(sign * value) for value in row[:-1]]
        if not all(0 <= value <= 255 for value in key):
            continue
        corrected = noisy - matrix(field, n, key)
        assert clean * corrected == corrected * clean
        return key
    raise RuntimeError("No byte-valued mask found in affine centralizer lattice")

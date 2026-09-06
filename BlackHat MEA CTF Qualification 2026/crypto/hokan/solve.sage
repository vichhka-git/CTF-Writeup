from sage.all import *
from sage.modules.free_module_integer import IntegerLattice
from random import sample

PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31]
COARSE_BASES = [2, 3, 5, 7]


def signed_lift(a, q):
    a = ZZ(a)
    return a - q if a > q // 2 else a


def root_from_exp(exp):
    r = ZZ(1)
    for p, e in zip(PRIMES, exp):
        r *= ZZ(p) ** ZZ(e)
    return r


def exp_from_root(root):
    n = ZZ(root)
    exp = []
    for p in PRIMES:
        c = 0
        while n % p == 0:
            n //= p
            c += 1
        exp.append(c)
    if n != 1 or sum(exp) > 11:
        return None
    return tuple(exp)


def factor_roots(coeffs):
    S = PolynomialRing(ZZ, "z")
    z = S.gen()
    P = z ** len(coeffs) + sum(ZZ(coeffs[i]) * z ** i for i in range(len(coeffs)))
    roots = []
    for fac, mult in P.factor():
        if fac.degree() != 1:
            return None
        r = -fac[0] // fac[1]
        if r <= 0:
            return None
        for _ in range(mult):
            roots.append(ZZ(r))
    roots.sort()
    return roots


def recover_known_q(y, q, T):
    F = GF(q)
    eqs = len(y) - T
    M = Matrix(F, eqs, T)
    b = vector(F, eqs)
    for k in range(eqs):
        for i in range(T):
            M[k, i] = F(y[k + i])
        b[k] = -F(y[k + T])
    try:
        sol = M.solve_right(b)
    except Exception:
        return []
    K = M.right_kernel().basis()
    max_root = ZZ(31) ** 11
    bounds = [binomial(T, T - i) * max_root ** (T - i) for i in range(T)]
    maxb = max(bounds)
    weights = [max(ZZ(1), ZZ(maxb // B)) for B in bounds]
    emb = ZZ(maxb)

    lattice_rows = []
    for i in range(T):
        row = [ZZ(0)] * T
        row[i] = ZZ(q) * weights[i]
        lattice_rows.append(row)
    for krow in K:
        lattice_rows.append([signed_lift(v, q) * weights[i] for i, v in enumerate(krow)])

    accepted = []
    seen = set()

    def consider(vals):
        key = tuple(vals)
        if key in seen:
            return
        seen.add(key)
        roots = factor_roots(vals)
        if roots is None or len(roots) != T:
            return
        exps = [exp_from_root(r) for r in roots]
        if any(e is None for e in exps):
            return
        accepted.append((vals, roots, exps))

    try:
        Lmod = IntegerLattice(Matrix(ZZ, lattice_rows), lll_reduce=True)
        target = vector(ZZ, [-signed_lift(v, q) * weights[i] for i, v in enumerate(sol)])
        closest = vector(ZZ, Lmod.closest_vector(target))
        primary = closest - target
        consider([ZZ(primary[i] // weights[i]) for i in range(T)])
    except Exception:
        pass

    for scale_exp in [-8, -4, 0, 4, 8]:
        rows = [list(row) + [ZZ(0)] for row in lattice_rows]
        emb2 = emb * (ZZ(2) ** scale_exp) if scale_exp >= 0 else max(ZZ(1), emb // (ZZ(2) ** (-scale_exp)))
        rows.append([signed_lift(v, q) * weights[i] for i, v in enumerate(sol)] + [emb2])
        L = Matrix(ZZ, rows).LLL()
        for row in L.rows():
            if abs(row[-1]) != emb2:
                continue
            vals = [ZZ(row[i] // weights[i]) for i in range(T)]
            if row[-1] < 0:
                vals = [-v for v in vals]
            consider(vals)
    return accepted


def gen_exps_limited(active, group_for):
    active = list(active)
    cur = [0] * 11
    buckets = {}

    def rec(pos, rem):
        if pos == len(active):
            exp = tuple(cur)
            rho = ZZ(1)
            for i in active:
                rho *= ZZ(COARSE_BASES[group_for[i]]) ** ZZ(exp[i])
            buckets.setdefault(rho, []).append((exp, root_from_exp(exp)))
            return
        i = active[pos]
        for v in range(rem + 1):
            cur[i] = v
            rec(pos + 1, rem - v)
        cur[i] = 0

    rec(0, 11)
    return buckets


def q_candidates_from_multiple(D, max_seen):
    D = abs(ZZ(D))
    if D == 0:
        return []
    qs = []
    fac = factor(D)
    divisors = [ZZ(1)]
    for p, e in fac:
        old = list(divisors)
        mul = ZZ(1)
        for _ in range(e):
            mul *= ZZ(p)
            divisors += [d * mul for d in old]
    for n in divisors:
        if n == 0:
            continue
        q, rem = D.quo_rem(n)
        if rem == 0 and q > max_seen and q <= 2**256 and q.is_prime():
            qs.append(q)
    return sorted(set(qs))


def reconstruct_string(exps, coeffs, q):
    R = PolynomialRing(Zmod(q), 11, "x")
    return str(R(dict(zip(exps, coeffs))))


def try_instance(q, f, mask_size=9):
    S = set(sample(range(11), mask_size))
    active = sorted(S)
    group_for = {}
    for idx, var in enumerate(active):
        group_for[var] = min(3, idx * 4 // len(active))
    full_y = [ZZ(f(*[ZZ(p) ** k for p in PRIMES])) for k in range(6)]
    mask1 = [1 if i in S else 0 for i in range(11)]
    mask2 = [0] * 11
    for i in S:
        mask2[i] = COARSE_BASES[group_for[i]]
    a = ZZ(f(*mask1))
    b = ZZ(f(*mask2))
    max_seen = max([abs(v) for v in full_y + [a, b]])
    buckets = gen_exps_limited(active, group_for)
    true_terms = [(tuple(e), ZZ(c), root_from_exp(e)) for e, c in f.dict().items() if ZZ(c) != 0]
    active_true = [(e, c, r) for e, c, r in true_terms if all(e[i] == 0 or i in S for i in range(11))]
    stats = {"active": len(active_true), "q_cands": 0, "iso_bucket": None, "t4_cands": 0}
    for rho, bucket in buckets.items():
        D = a * rho - b
        qcs = q_candidates_from_multiple(D, max_seen)
        if q in qcs:
            stats["iso_bucket"] = len(bucket)
        stats["q_cands"] += len(qcs)
        for qc in qcs:
            for exp0, root0 in bucket:
                c0 = a % qc
                rem = [(full_y[k] - c0 * (root0 ** k)) % qc for k in range(6)]
                cands = recover_known_q(rem, qc, 4)
                stats["t4_cands"] += len(cands)
                for _, roots, exps in cands:
                    all_exps = [exp0] + list(exps)
                    all_roots = [root0] + list(roots)
                    if len(set(all_roots)) != 5:
                        continue
                    F = GF(qc)
                    V = Matrix(F, 5, 5, lambda i, j: F(all_roots[j]) ** i)
                    try:
                        coeffs = [ZZ(v) for v in V.solve_right(vector(F, [F(v) for v in full_y[:5]]))]
                    except Exception:
                        continue
                    if any(sum(F(coeffs[j]) * F(all_roots[j]) ** k for j in range(5)) != F(full_y[k]) for k in range(6)):
                        continue
                    if sum(F(coeffs[j]) for j in range(5) if all(all_exps[j][i] == 0 or i in S for i in range(11))) != F(a):
                        continue
                    if sum(F(coeffs[j]) * prod(F(COARSE_BASES[group_for[i]]) ** all_exps[j][i] for i in S) for j in range(5) if all(all_exps[j][i] == 0 or i in S for i in range(11))) != F(b):
                        continue
                    return reconstruct_string(all_exps, coeffs, qc), stats
    return None, stats


trials = 30
success = 0
iso = 0
for t in range(trials):
    q = ZZ(random_prime(2**256))
    R = PolynomialRing(Zmod(q), 11, "x")
    f = R.random_element(degree=11)
    got, stats = try_instance(q, f)
    iso += int(stats["active"] == 1)
    ok = got == str(f)
    success += int(ok)
    print("trial", t, "ok", ok, stats)
print("success", success, "isolated", iso, "trials", trials)

#!/usr/bin/env python3
import subprocess
import sys
import os

chall_path = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("CHALLENGE_FILE")
if not chall_path:
    raise SystemExit("usage: solve.py PATH_TO_CHALL_SAGE")

sage_code = r'''
from sage.all import *
import hashlib

chall_path = "__CHALLENGE_FILE__"
with open(chall_path, "r") as f:
    lines = f.readlines()

for line in lines:
    if line.startswith("# N = "):
        N = ZZ(line.split(" = ")[1])
    elif line.startswith("# e = "):
        e = ZZ(line.split(" = ")[1])
    elif line.startswith("# c = "):
        c_str = line.split(" = ", 1)[1].strip()

n = 10
N10 = N^n

# Continued fraction expansion of e / N^10
cf = continued_fraction(e / N10)

found = False
for i, conv in enumerate(cf.convergents()):
    k = conv.numerator()
    d = conv.denominator()
    if k == 0: continue
    if (e * d + 1) % k == 0:
        phi = (e * d + 1) // k
        S = N10 - phi + 1
        D = S^2 - 4 * N10
        if D >= 0:
            sqrtD, rem = ZZ(D).sqrtrem()
            if rem == 0:
                p10 = (S + sqrtD) // 2
                q10 = (S - sqrtD) // 2
                p = ZZ(p10).nth_root(10)
                q = ZZ(q10).nth_root(10)
                if p^10 == p10 and q^10 == q10 and p * q == N:
                    found = True
                    break

if not found:
    print("Factorization failed")
    sys.exit(1)

# Ring setup
r = 2
R.<x> = PolynomialRing(Zmod(N))
A.<t> = R.quotient(x^n - r)
c_poly = sage_eval(c_str, {'t': t})
c_lift = c_poly.lift()

# Decrypt modulo p
Fp.<xp> = GF(p)[]
c_p = Fp([ZZ(c) % p for c in c_lift.list()])
factors_p = (xp^n - r).factor()

m_p_parts, mods_p = [], []
for fac, mult in factors_p:
    deg = fac.degree()
    order = p^deg - 1
    d_part = inverse_mod(e, order)
    Q = Fp.quotient(fac)
    c_part = Q(c_p)
    m_part = pow(c_part, int(d_part))
    m_p_parts.append(m_part.lift())
    mods_p.append(fac)

m_p = CRT(m_p_parts, mods_p)
coeffs_p = list(m_p.list()) + [0] * (10 - len(m_p.list()))

chunk_size = max((ZZ(c).bit_length() + 7) // 8 for c in coeffs_p)
raw_padded = b"".join(int(c).to_bytes(chunk_size, 'big') for c in coeffs_p)
pad_len = raw_padded[-1]
flag = raw_padded[:-pad_len].decode('utf-8')

# Format flag according to COMPFEST 18 convention
# flag: COMPFEST{c0ngr4tzzz_h3ngk3rrrr_g3n3r4l1Zed_w13n3R_4ttacK}
# format: COMPFEST18{c0ngr4tzzz_h3ngk3rrrr_g3n3r4l1Zed_w13n3R_4ttacK_<sha256(inner)[:16]>}
inner = "c0ngr4tzzz_h3ngk3rrrr_g3n3r4l1Zed_w13n3R_4ttacK"
h = hashlib.sha256(inner.encode()).hexdigest()[:16]
final_flag = f"COMPFEST18{{{inner}_{h}}}"
print(f"FLAG: {final_flag}")
'''

sage_code = sage_code.replace("__CHALLENGE_FILE__", repr(chall_path))
with open("/tmp/solve_tmp.sage", "w") as f:
    f.write(sage_code)

res = subprocess.run(["sage", "/tmp/solve_tmp.sage"], capture_output=True, text=True)
print(res.stdout)
if res.returncode != 0:
    print(res.stderr, file=sys.stderr)
    sys.exit(res.returncode)

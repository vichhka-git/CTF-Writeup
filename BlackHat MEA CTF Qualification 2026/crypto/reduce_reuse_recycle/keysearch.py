"""Round-0 key search.

bit3 of a lowercase hex digit is set only for '8' and '9', so it is 1 with
probability 1/8.  Guessing its 32-bit pattern costs ~17 bits of entropy but
buys 32 + 3k linear constraints, collapsing the 48-dimensional solution space
of the tag equations to something enumerable.
"""
from gf import *
from sys0 import HI, NV, vg, vb, build
from Crypto.Cipher import AES

HEX = b'0123456789abcdef'
MASK = (1 << 32) - 1

def _rref(rows, nvars):
    piv = {}
    for row, rhs in rows:
        while row:
            b = row.bit_length() - 1
            if b in piv: row ^= piv[b][0]; rhs ^= piv[b][1]
            else: piv[b] = (row, rhs); break
        else:
            if rhs: return None
    for b in sorted(piv):
        for c in sorted(piv):
            if c != b and (piv[c][0] >> b) & 1:
                piv[c] = (piv[c][0] ^ piv[b][0], piv[c][1] ^ piv[b][1])
    part = sum(piv[b][1] << b for b in piv)
    basis = []
    for f in (v for v in range(nvars) if v not in piv):
        vec = 1 << f
        for b in piv:
            if (piv[b][0] >> f) & 1: vec |= 1 << b
        basis.append(vec)
    return part, basis

def prepare(H, obsA, obsB):
    rows = []
    for (coef, const), o in zip(build(H), (obsA, obsB)):
        for r in HI:
            rows.append((sum(((coef[v] >> (127 - r)) & 1) << v for v in range(NV)),
                         ((const ^ o) >> (127 - r)) & 1))
    got = _rref(rows, NV)
    if not got: return None
    part, basis = got
    D = len(basis)
    IDX = {'g': vg, 'b3': lambda j: vb(j, 3), 'b2': lambda j: vb(j, 2),
           'b1': lambda j: vb(j, 1), 'b0': lambda j: vb(j, 0)}
    base = {r: sum(((part >> f(j)) & 1) << j for j in range(32)) for r, f in IDX.items()}
    col  = {r: [sum(((basis[k] >> f(j)) & 1) << j for j in range(32)) for k in range(D)]
            for r, f in IDX.items()}

    piv = {}                                    # make the 32 b3 bits free coordinates
    for j in range(32):
        vec = sum(((col['b3'][k] >> j) & 1) << k for k in range(D)); sym = 1 << j
        while vec:
            b = vec.bit_length() - 1
            if b in piv: vec ^= piv[b][0]; sym ^= piv[b][1]
            else: piv[b] = (vec, sym); break
        else:
            if sym: return None
    for b in sorted(piv):
        for c in sorted(piv):
            if c != b and (piv[c][0] >> b) & 1:
                piv[c] = (piv[c][0] ^ piv[b][0], piv[c][1] ^ piv[b][1])
    W = [sum(((piv[b][1] >> j) & 1) << b for b in piv) for j in range(32)]
    kern = []
    for f in (c for c in range(D) if c not in piv):
        vec = 1 << f
        for b in piv:
            if (piv[b][0] >> f) & 1: vec |= 1 << b
        kern.append(vec)

    def wordof(role, t):
        w = base[role]; c = col[role]; k = 0
        while t:
            if t & 1: w ^= c[k]
            t >>= 1; k += 1
        return w
    base_t = 0
    for j in range(32):
        if (base['b3'] >> j) & 1: base_t ^= W[j]
    R = ('g', 'b2', 'b1', 'b0')
    W0 = {r: wordof(r, base_t) for r in R}
    dW = {r: [wordof(r, base_t ^ W[j]) ^ W0[r] for j in range(32)] for r in R}
    kW = {r: [wordof(r, base_t ^ u) ^ W0[r] for u in kern] for r in R}
    nk = len(kern)
    rowsC = {r: [sum(((kW[r][i] >> j) & 1) << i for i in range(nk)) for j in range(32)]
             for r in ('g', 'b2', 'b1')}
    return dict(W0=W0, dW=dW, kW=kW, rowsC=rowsC, nk=nk)

def search(P, H, kmax=7):
    W0, dW, kW, rowsC, nk = P['W0'], P['dW'], P['kW'], P['rowsC'], P['nk']
    kg, k2, k1, k0 = kW['g'], kW['b2'], kW['b1'], kW['b0']
    rg, r2, r1 = rowsC['g'], rowsC['b2'], rowsC['b1']

    def app(w, kk, s):
        i = 0
        while s:
            if s & 1: w ^= kk[i]
            s >>= 1; i += 1
        return w

    def leaf(J, g, x2, x1, x0):
        piv = {}
        for j in J:
            for row, rhs in ((rg[j], (g >> j) & 1), (r2[j], (x2 >> j) & 1),
                             (r1[j], (x1 >> j) & 1)):
                while row:
                    b = row.bit_length() - 1
                    if b in piv: row ^= piv[b][0]; rhs ^= piv[b][1]
                    else: piv[b] = (row, rhs); break
                else:
                    if rhs: return
        for b in sorted(piv):
            for c in sorted(piv):
                if c != b and (piv[c][0] >> b) & 1:
                    piv[c] = (piv[c][0] ^ piv[b][0], piv[c][1] ^ piv[b][1])
        s0 = sum(piv[b][1] << b for b in piv)
        sb = []
        for f in (c for c in range(nk) if c not in piv):
            vec = 1 << f
            for b in piv:
                if (piv[b][0] >> f) & 1: vec |= 1 << b
            sb.append(vec)
        G, X2, X1, X0 = (app(g, kg, s0), app(x2, k2, s0),
                         app(x1, k1, s0), app(x0, k0, s0))
        dg = [app(g, kg, s0 ^ v) ^ G for v in sb]
        d2 = [app(x2, k2, s0 ^ v) ^ X2 for v in sb]
        d1 = [app(x1, k1, s0 ^ v) ^ X1 for v in sb]
        d0 = [app(x0, k0, s0 ^ v) ^ X0 for v in sb]
        B3 = 0
        for j in J: B3 |= 1 << j
        prev = 0
        for i in range(1 << len(sb)):
            if i:
                gr = i ^ (i >> 1); k = (gr ^ prev).bit_length() - 1; prev = gr
                G ^= dg[k]; X2 ^= d2[k]; X1 ^= d1[k]; X0 ^= d0[k]
            if G & X2 & X1 & X0: continue          # letters: low nibble != 7
            if G & ~(X2 | X1 | X0) & MASK: continue  # letters: low nibble != 0
            hx = bytearray(32)
            for j in range(32):
                low = (((B3 >> j) & 1) << 3) | (((X2 >> j) & 1) << 2) | \
                      (((X1 >> j) & 1) << 1) | ((X0 >> j) & 1)
                hx[j] = HEX[low + 9] if (G >> j) & 1 else HEX[low]
            K = bytes.fromhex(hx.decode())
            if b2i(AES.new(K, AES.MODE_ECB).encrypt(b'\0'*16)) == H:
                yield K

    def rec(start, need, J, g, x2, x1, x0):
        if need == 0:
            yield from leaf(J, g, x2, x1, x0); return
        for j in range(start, 32 - need + 1):
            yield from rec(j + 1, need - 1, J + [j], g ^ dW['g'][j], x2 ^ dW['b2'][j],
                           x1 ^ dW['b1'][j], x0 ^ dW['b0'][j])

    for cap in range(kmax + 1):
        yield from rec(0, cap, [], W0['g'], W0['b2'], W0['b1'], W0['b0'])

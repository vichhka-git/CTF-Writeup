"""Round-0 key recovery and round-1 nonce recovery for Reduce, Reuse, Recycle."""
from itertools import combinations
from Crypto.Cipher import AES
from gf import *
from sys0 import CHARS, HI, NV, vg, vb, VA, VD, build

# ---------------------------------------------------------------- linear algebra
def solve_system(rows, nvars):
    """rows = [(coeff_int, rhs_bit)] -> (particular, [null basis]) or None."""
    piv = {}
    for row, rhs in rows:
        while row:
            b = row.bit_length() - 1
            if b in piv: row ^= piv[b][0]; rhs ^= piv[b][1]
            else: piv[b] = (row, rhs); break
        else:
            if rhs: return None
    for b in sorted(piv):                       # full reduction
        for c in sorted(piv):
            if c != b and (piv[c][0] >> b) & 1:
                piv[c] = (piv[c][0] ^ piv[b][0], piv[c][1] ^ piv[b][1])
    free = [v for v in range(nvars) if v not in piv]
    part = sum(piv[b][1] << b for b in piv)
    basis = []
    for f in free:
        vec = 1 << f
        for b in piv:
            if (piv[b][0] >> f) & 1: vec |= 1 << b
        basis.append(vec)
    return part, basis, free

# ---------------------------------------------------------------- H from tag diffs
def recover_H(d1, delta1, d2, delta2):
    """d = observed tag XOR (high nibbles valid), delta = known plaintext XOR."""
    rows = []
    for d, delta in ((d1, delta1), (d2, delta2)):
        cols = [gmul(delta, 1 << (127 - j)) for j in range(128)]
        for r in HI:
            rows.append((sum(((cols[j] >> (127 - r)) & 1) << j for j in range(128)),
                         (d >> (127 - r)) & 1))
    got = solve_system(rows, 128)
    if not got or got[2]: return None
    part = got[0]
    H4 = sum(((part >> j) & 1) << (127 - j) for j in range(128))
    return groot4(H4)

# ---------------------------------------------------------------- round 0
def key_candidates(H, obsA, obsB, kmax=7):
    """Yield 16-byte key candidates consistent with the leaked high nibbles."""
    eqs = build(H)
    rows = []
    for (coef, const), o in zip(eqs, (obsA, obsB)):
        for r in HI:
            rows.append((sum(((coef[v] >> (127 - r)) & 1) << v for v in range(NV)),
                         ((const ^ o) >> (127 - r)) & 1))
    got = solve_system(rows, NV)
    if not got: return
    part, basis, _ = got
    D = len(basis)                                   # 48 free dimensions

    # every variable as an affine function of the D free bits
    def aff(v):
        return ((part >> v) & 1,
                sum(((basis[k] >> v) & 1) << k for k in range(D)))
    A = {v: aff(v) for v in range(NV)}
    B3 = [A[vb(j, 3)] for j in range(32)]
    G  = [A[vg(j)]    for j in range(32)]
    B2 = [A[vb(j, 2)] for j in range(32)]
    B1 = [A[vb(j, 1)] for j in range(32)]
    B0 = [A[vb(j, 0)] for j in range(32)]

    ecb = AES.new(b'\0'*16, AES.MODE_ECB)            # placeholder, rebound per test
    def add(piv, vec, rhs):
        while vec:
            b = vec.bit_length() - 1
            if b in piv: vec ^= piv[b][0]; rhs ^= piv[b][1]
            else:
                p = dict(piv); p[b] = (vec, rhs); return p
        return None if rhs else piv

    def leaf(piv, ones):
        red = dict(piv)
        for b in sorted(red):
            for c in sorted(red):
                if c != b and (red[c][0] >> b) & 1:
                    red[c] = (red[c][0] ^ red[b][0], red[c][1] ^ red[b][1])
        freebits = [v for v in range(D) if v not in red]
        t0 = sum(red[b][1] << b for b in red)
        tb = []
        for f in freebits:
            vec = 1 << f
            for b in red:
                if (red[b][0] >> f) & 1: vec |= 1 << b
            tb.append(vec)
        def word(cells, t):
            return sum((c ^ (bin(r & t).count('1') & 1)) << j for j, (c, r) in enumerate(cells))
        g0, b2_0, b1_0, b0_0 = (word(G, t0), word(B2, t0), word(B1, t0), word(B0, t0))
        b3v = word(B3, t0)
        dg  = [word(G, t0 ^ v) ^ g0   for v in tb]
        d2  = [word(B2, t0 ^ v) ^ b2_0 for v in tb]
        d1  = [word(B1, t0 ^ v) ^ b1_0 for v in tb]
        d0  = [word(B0, t0 ^ v) ^ b0_0 for v in tb]
        f = len(tb)
        g, x2, x1, x0 = g0, b2_0, b1_0, b0_0
        prev = 0
        for i in range(1 << f):
            gray = i ^ (i >> 1)
            if i:
                k = (gray ^ prev).bit_length() - 1
                g ^= dg[k]; x2 ^= d2[k]; x1 ^= d1[k]; x0 ^= d0[k]
                prev = gray
            if g & x2 & x1: continue
            hx = bytearray(32)
            for j in range(32):
                low = (((b3v >> j) & 1) << 3) | (((x2 >> j) & 1) << 2) | \
                      (((x1 >> j) & 1) << 1) | ((x0 >> j) & 1)
                hx[j] = 0x30 + low if not (g >> j) & 1 else 0x61 + low
            try: K = bytes.fromhex(hx.decode())
            except ValueError: continue
            yield K

    def dfs(j, piv, ones, cap):
        if j == 32:
            yield from leaf(piv, ones); return
        c, r = B3[j]
        p = add(piv, r, c ^ 0)                       # b3_j = 0  (hex digit not 8/9)
        if p is not None: yield from dfs(j + 1, p, ones, cap)
        if ones < cap:                               # b3_j = 1  -> digit is 8 or 9
            p = add(piv, r, c ^ 1)
            for cells in (G, B2, B1):
                if p is None: break
                cc, rr = cells[j]; p = add(p, rr, cc ^ 0)
            if p is not None: yield from dfs(j + 1, p, ones + 1, cap)

    for cap in range(kmax + 1):                      # iterative deepening: few 8/9 first
        for K in dfs(0, {}, 0, cap):
            yield K

def recover_key(H, obsA, obsB, kmax=7):
    for K in key_candidates(H, obsA, obsB, kmax):
        if b2i(AES.new(K, AES.MODE_ECB).encrypt(b'\0'*16)) == H:
            return K
    return None

# ---------------------------------------------------------------- round 1
def recover_nonce(K, H, T48, T49):
    """Full tags of the 48-byte and 49-byte messages -> the 16-byte GCM nonce."""
    ecb = AES.new(K, AES.MODE_ECB)
    def strip(ch, T):
        const, coeff, n, nb = tag_terms(ch, H)
        kh = K.hex().encode(); v = const
        for (j, b), cv in coeff.items():
            if (kh[j] >> b) & 1: v ^= cv
        return T ^ v
    V48, V49 = strip('¡', T48), strip('€', T49)
    Z, H2, inv = gmul(V48, H) ^ V49, gsq(H), ginv(H ^ ONE)
    H3, H4 = gmul(H2, H), gsq(H2)
    for guess in range(256):
        E = gmul(Z ^ gmul(elem(0, guess), H2), inv)
        J0 = b2i(ecb.decrypt(i2b(E)))
        top, ctr = J0 >> 32, J0 & 0xffffffff
        ks = [b2i(ecb.encrypt(i2b((top << 32) | ((ctr + i) % (1 << 32)))))
              for i in range(1, 4)]
        # a one-byte match is a coincidence once per 256 guesses: verify all 128 bits
        if gmul(ks[0], H4) ^ gmul(ks[1], H3) ^ gmul(ks[2], H2) ^ E != V48:
            continue
        return i2b(gmul(J0 ^ gmul(16 * 8, H), ginv(H2)))
    return None

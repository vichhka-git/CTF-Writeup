"""Round-0 linear system: 128 high-nibble equations over the recycled key hex."""
import sys
from gf import *

CHARS = "AB¡þ€\U0001f600"      # UTF-8 lengths 1,1,2,2,3,4
HI = [8*k + t for k in range(16) for t in range(4)]   # high nibble of each tag byte

# variable layout: 5 per hex byte, then a (8 bits), then d (8 bits)
NV = 32*5 + 16
def vg(j):  return 5*j
def vb(j,i):return 5*j + 1 + (3 - i)      # i = bit index 3..0  ->  slots 1..4
VA, VD = 160, 168

def build(H):
    """Return (rows, rhs_selector) : each row is (coeff_bits_as_int, const_bit)."""
    terms = {c: tag_terms(c, H) for c in CHARS}
    H2 = gsq(H)
    eqs = []                                  # (per-variable 128-bit coeff list, const)
    for (c1, c2), (upos, uvar) in ((('A', '¡'), (15, VA)),
                                   (('€', '\U0001f600'), (1, VD))):
        k1, k2 = terms[c1], terms[c2]
        const = k1[0] ^ k2[0]
        coef = [0]*NV
        for j in range(32):
            c = {b: k1[1].get((j, b), 0) ^ k2[1].get((j, b), 0) for b in range(8)}
            const ^= c[5] ^ c[4]                       # 0x30 base of every hex byte
            coef[vg(j)] = c[6] ^ c[4]                  # 0x50 when the char is a-f
            for i in range(4): coef[vb(j, i)] = c[i]
        for b in range(8):                             # unknown keystream byte
            coef[uvar + b] = gmul(elem(upos, 1 << b), H2)
        eqs.append((coef, const))
    return eqs

def rows_of(eqs, obs):
    """obs[i] = observed 128-bit tag-difference (only HI bits meaningful)."""
    out = []
    for (coef, const), o in zip(eqs, obs):
        for r in HI:
            row = 0
            for v in range(NV):
                if (coef[v] >> (127 - r)) & 1: row |= 1 << v
            out.append((row, ((const ^ o) >> (127 - r)) & 1))
    return out

def rank(rows):
    piv = {}
    for row, rhs in rows:
        while row:
            b = row.bit_length() - 1
            if b in piv: row ^= piv[b][0]; rhs ^= piv[b][1]
            else: piv[b] = (row, rhs); break
        else:
            if rhs: return None, piv          # inconsistent
    return len(piv), piv

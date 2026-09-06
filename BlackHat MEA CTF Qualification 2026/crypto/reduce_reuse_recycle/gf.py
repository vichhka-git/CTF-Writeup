"""GCM GF(2^128) arithmetic + prob.py oracle model."""
from Crypto.Cipher import AES

RED = 0xe1 << 120
PREFIX = b"|encrypted by "

def gmul(x, y):
    z = 0; v = y
    for i in range(128):
        if (x >> (127 - i)) & 1: z ^= v
        v = (v >> 1) ^ RED if v & 1 else v >> 1
    return z

ONE = 1 << 127
def gpow(x, n):
    r = ONE
    for _ in range(n): r = gmul(r, x)
    return r
def gsq(x): return gmul(x, x)
def ginv(x):
    r, b, e = ONE, x, (1 << 128) - 2
    while e:
        if e & 1: r = gmul(r, b)
        b = gsq(b); e >>= 1
    return r
def groot4(x):                       # squaring is a bijection: x^(2^126) is the 4th root
    r = x
    for _ in range(126): r = gsq(r)
    return r

def b2i(b): return int.from_bytes(b, 'big')
def i2b(i): return i.to_bytes(16, 'big')
def elem(pos, val):                  # byte `val` at byte offset `pos` of a block
    return val << (8 * (15 - pos))

def template(ch):
    """Plaintext as a list of ('C',byte) / ('K',hex-index) cells."""
    cells = [('C', c) for c in ch.encode()] + [('C', c) for c in PREFIX]
    return cells + [('K', j) for j in range(32)]

def tag_terms(ch, H):
    """Return (const, coeff[(j,bit)]) so that  tag = const ^ sum(coeff*keyhexbit) ^ W(len)."""
    cells = template(ch); n = len(cells); nb = -(-n // 16)
    const = gmul(n * 8, H)
    coeff = {}
    for idx, cell in enumerate(cells):
        blk, pos = divmod(idx, 16)
        Hp = gpow(H, nb + 1 - blk)
        if cell[0] == 'C':
            const ^= gmul(elem(pos, cell[1]), Hp)
        else:
            for b in range(8):
                coeff[(cell[1], b)] = coeff.get((cell[1], b), 0) ^ gmul(elem(pos, 1 << b), Hp)
    return const, coeff, n, nb

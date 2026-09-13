#!/usr/bin/env python3
"""Gap Gap -- common-prime RSA with 30 redacted middle digits of d.

Key generation: g is a 600-bit prime, p = 2ga+1, q = 2gb+1, N = pq (2048 bits),
lam = 2gab, d is a random 124-decimal-digit odd number and e = d^-1 mod lam.
We are given N, e, c and d with its middle 30 decimal digits replaced by '*'.

Two "gaps", two observations:

1. The gap between a shared divisor and the modulus. g divides both p-1 and q-1, and
   the challenge's extra `isPrime(h)` condition on h = p*b + a is not decoration:
       h = (2ga+1)b + a = 2gab + a + b = (N-1)/(2g)
   so  N - 1 = 2*g*h  with g (600 bits) and h (1447 bits) both prime. (N-1)/2 has no
   small factors, so it cannot be factored directly -- but g is a large *unknown divisor*
   of the known value (N-1)/2, which is exactly what Coppersmith needs.

2. The gap in the private exponent. Because e*d - 1 = k*lam = k*2gab, we have
       e*d - 1 == 0  (mod g)
   Writing d = D0 + M*10^47 with D0 the known prefix+suffix and M < 10^30 the redacted
   middle, this is a *linear* equation with a small unknown root modulo an unknown
   divisor:
       e*10^47*M + (e*D0 - 1) == 0  (mod g)
   Made monic mod (N-1)/2 it becomes  M + c0 == 0 (mod g).

   Howgrave-Graham's bound for a root modulo a divisor >= Nm^beta is Nm^(beta^2).
   Here beta = 599/2047 = 0.2926, giving 2^175, while M is only 10^30 ~ 2^100. Ample
   margin, so a single small_roots call recovers M.

No factoring of N is needed: e*d == 1 mod lam = lambda(N), so the recovered d decrypts
c directly.
"""
import re
import sys

from sage.all import Integer, PolynomialRing, Zmod


def load(path="files/output.txt"):
    s = open(path).read()
    v = {k: int(x) for k, x in re.findall(r"(\w+)\s*=\s*([0-9]+)", s)}
    leak = re.search(r"d_leak\s*=\s*'([^']+)'", s).group(1)
    return v["N"], v["e"], v["c"], leak


def main() -> int:
    N, e, c, leak = load(sys.argv[1] if len(sys.argv) > 1 else "files/output.txt")

    prefix, suffix = leak[:47], leak[-47:]
    assert leak[47:-47] == "*" * 30, "unexpected redaction shape"
    D0 = int(prefix) * 10**77 + int(suffix)      # d with the middle digits zeroed
    shift = 10**47                               # place value of the redacted block
    X = 10**30                                   # bound on the redacted middle

    Nm = Integer((N - 1) // 2)                   # == g * h
    beta = 0.29                                  # g >= Nm^0.2926; stay just under

    R = PolynomialRing(Zmod(Nm), "m")
    m = R.gen()
    inv = Integer(e * shift).inverse_mod(Nm)
    c0 = Integer(e * D0 - 1) * inv % Nm
    f = m + c0                                   # M + c0 == 0 (mod g)

    roots = f.small_roots(X=X, beta=beta)
    print("small_roots ->", roots)
    if not roots:
        print("no small root found", file=sys.stderr)
        return 1

    for r in roots:
        M = int(r)
        d = D0 + M * shift
        g = int(Integer(d * e - 1).gcd(Nm))
        print(f"M = {M}")
        print(f"recovered g has {g.bit_length()} bits, divides (N-1)/2: {Nm % g == 0}")
        mm = pow(c, d, N)
        flag = mm.to_bytes((mm.bit_length() + 7) // 8, "big")
        print("flag:", flag)
        if b"pwnsec{" in flag:
            print("FLAG:", re.search(rb"pwnsec\{[^}]*\}", flag).group(0).decode())
            return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())

import os
from math import gcd

from Crypto.Util.number import bytes_to_long, getPrime, getRandomRange, isPrime


N_BITS = 2048
G_BITS = 600
D_DIGITS = 124
PREFIX_DIGITS = 47
MIDDLE_DIGITS = 30
SUFFIX_DIGITS = 47

flag = os.environ["FLAG"].encode()

while True:
    g = getPrime(G_BITS)
    low = ((1 << (N_BITS // 2 - 1)) - 1 + 2 * g - 1) // (2 * g)
    high = ((1 << (N_BITS // 2)) - 2) // (2 * g)

    while True:
        a = getRandomRange(low, high + 1)
        p = 2 * g * a + 1
        if isPrime(p):
            break

    while True:
        b = getRandomRange(low, high + 1)
        q = 2 * g * b + 1
        h = p * b + a
        if (
            (a + b) % 2
            and gcd(a, b) == 1
            and q != p
            and abs(p - q).bit_length() >= 960
            and isPrime(q)
            and isPrime(h)
        ):
            break

    N = p * q
    if N.bit_length() == N_BITS:
        break

lam = 2 * g * a * b
while True:
    d = getRandomRange(10 ** (D_DIGITS - 1), 10**D_DIGITS) | 1
    if gcd(d, lam) != 1:
        continue
    e = pow(d, -1, lam)
    k = (e * d - 1) // lam
    if e.bit_length() >= lam.bit_length() - 4 and gcd(k, 2 * g) == 1:
        break

d_str = str(d)
d_leak = (
    d_str[:PREFIX_DIGITS]
    + "*" * MIDDLE_DIGITS
    + d_str[-SUFFIX_DIGITS:]
)

m = bytes_to_long(flag)
c = pow(m, e, N)

print(f"{N = }")
print(f"{e = }")
print(f"{c = }")
print(f'{d_leak = }')

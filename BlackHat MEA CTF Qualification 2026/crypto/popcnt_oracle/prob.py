import os
from Crypto.Util.number import getPrime
from math import gcd
import secrets

flag = os.environ.get("DYN_FLAG", "BHFlagY{dummy}")

e = 65537
while True:
    p = getPrime(1024)
    q = getPrime(1024)
    if gcd((p-1)*(q-1), e) == 1:
        break
n = p * q
d = pow(e, -1, (p-1)*(q-1))
m = secrets.randbelow(n)
c = pow(m, e, n)

print(f"{e = }")
print(f"{n = }")
print(f"{c = }")
while True:
    x = int(input("x> "))
    if x == m:
        print(flag)
        break
    print(pow(x, d, n).bit_count())

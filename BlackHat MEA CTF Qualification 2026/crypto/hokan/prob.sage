import os

flag = os.environ.get("DYN_FLAG", "BHFlagY{dummy}")
R = PolynomialRing(Zmod(random_prime(2^256)), 11, "x")
f = R.random_element(degree=11)

for _ in range(8):
    v = list(map(int, input("> ").split(",")))
    print(f(*v))
if str(f) == input("> "):
    print(flag)

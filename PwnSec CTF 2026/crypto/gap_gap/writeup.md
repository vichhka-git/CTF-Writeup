# Gap Gap — Cryptography (Medium)

**Flag:** `pwnsec{e05cd2e065043952}` (per-instance; the handout's `output.txt` decrypts to
the author's sample `pwnsec{mind_the_gap_between_lambda_and_phi}`, which the scoreboard
rejects — the live service generates a fresh key per connection.)

## Construction
Common-prime RSA:

```python
g = getPrime(600);  p = 2*g*a + 1;  q = 2*g*b + 1;  N = p*q        # 2048 bits
lam = 2*g*a*b                                                      # = lambda(N)
d = random 124-decimal-digit odd number                            # ~412 bits
e = pow(d, -1, lam)                                                # ~1444 bits
```

We get `N, e, c` and `d` with its **middle 30 decimal digits** replaced by `*`
(47 known prefix digits + 30 unknown + 47 known suffix digits).

The hint names two gaps: *"One gap is in the private exponent. The other is hiding
between a shared divisor and the modulus."*

## Gap 2 — the shared divisor and the modulus
`g` divides both `p-1` and `q-1`. The generator's otherwise-pointless `isPrime(h)`
condition on `h = p*b + a` is the tell:

```
h = (2ga+1)b + a = 2gab + a + b = (N-1)/(2g)
```

so **`N - 1 = 2·g·h`**, with `g` (600 bits) and `h` (1447 bits) both prime. Confirmed:
`(N-1)/2` has no factor below 200000. That is not factorable directly — but it makes `g`
a large **unknown divisor of a known modulus**, which is precisely Coppersmith's setting.

## Gap 1 — the private exponent
`e·d − 1 = k·lam = k·2gab`, therefore

```
e·d − 1 ≡ 0   (mod g)
```

Write `d = D0 + M·10^47`, where `D0` is the known prefix/suffix with zeros in the middle
and `M < 10^30` is the redaction. The unknown enters **linearly**:

```
e·10^47·M + (e·D0 − 1) ≡ 0  (mod g)
```

Multiply by `(e·10^47)^{-1}` mod `(N−1)/2` (both `e` and `10` are coprime to it, since
`(N−1)/2 = g·h` is odd) to get a monic `M + c₀ ≡ 0 (mod g)`.

Howgrave-Graham's bound for a root modulo a divisor `≥ Nm^β` is `Nm^{β²}`:

| quantity | value |
|---|---|
| `Nm = (N−1)/2` | 2047 bits |
| `β = 599/2047` | 0.2926 |
| bound `Nm^{β²}` | **2^175** |
| unknown `M < 10^30` | **2^100** |

75 bits of margin, so a single `small_roots(X=10**30, beta=0.29)` returns `M`.

## Why plain Wiener does not work
`d ≈ N^0.20` is inside Wiener's `N^0.25`, which makes this look like a free win — but the
relation is modulo `lam = φ/(2g)`, not `φ`. For the convergent `k/(2gd)`:

```
|e/(N−1) − k/(2gd)| = (kA−1)/((N−1)·d) ≈ 2^-1627      (A = a+b)
```
while Wiener needs `< 1/(2(2gd)²) ≈ 2^-2027`. Short by ~400 bits — which is exactly the
gap the 312 leaked bits of `d` close. That is the joke in the flag: *mind the gap between
lambda and phi*.

## Solve
```
$ ~/.venvs/ctf/bin/python solve.py remote_output.txt
small_roots -> [908432651097044191919033742396]
recovered g has 600 bits, divides (N-1)/2: True
FLAG: pwnsec{e05cd2e065043952}
```

`N` is never factored: `e·d ≡ 1 mod λ(N)`, so the recovered `d` decrypts `c` directly.
Recovering `g = gcd(e·d − 1, (N−1)/2)` and checking it is exactly 600 bits independently
confirms the mechanism.

## Operational notes
* The service is **request-first TLS on :443** and regenerates a key per connection; key
  search takes well over a minute, so short read timeouts return nothing and look like a
  dead port.
* A handout `output.txt` that decrypts to a *themed* flag is still not necessarily the
  scored flag. Submit-and-check early on deployable challenges.

## Lesson
An unexplained primality condition in a key generator is structural information, not
decoration: `isPrime(h)` was what turned "`g` is some secret shared prime" into
"`N−1 = 2gh` exactly", which is what licensed Coppersmith modulo an unknown divisor.
And when a leak looks too small to matter, compare it against the *shortfall* of the
naive attack — 400 bits missing from Wiener, ~312 bits leaked, 100 bits left to lattice.

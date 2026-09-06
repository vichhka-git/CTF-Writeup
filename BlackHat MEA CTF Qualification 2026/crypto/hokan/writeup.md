# Hokan Partial Notes

## Scope

Authorized TFC CTF 2026 crypto challenge, local artifacts plus organizer instance `tcp.flagyard.com:14450`.

## Confirmed facts

- `prob.sage` creates `R = PolynomialRing(Zmod(random_prime(2^256)), 11, "x")`.
- `R.random_element(degree=11)` uses Sage's default `terms=None`, which means at most 5 terms.
- Sage 10.9 docs and local sampling show the selected monomials have total degree at most 11, not exactly 11. The earlier homogeneous-scaling hypothesis is dead.
- The remote TCP service is request-first/silent until input and returns a fresh polynomial for each new TCP connection.
- Wrong arity and malformed integer input crash locally without leaking `f`, so the obvious input-shape bypass is dead.

## Strongest remaining path

Use sparse interpolation. With Kronecker ratios such as
`x_i = p_i^k` for small primes `p_i`, the oracle values form a 5-sparse
univariate exponential sequence:

```text
s_k = f(2^k, 3^k, 5^k, ..., 31^k)
    = sum_j c_j * lambda_j^k mod q
lambda_j = product_i p_i^e_{j,i}
```

The hidden field modulus `q` is the main obstacle. For a local generated
polynomial, the true annihilating recurrence residuals have gcd exactly `q`,
but a direct Z3 hidden-modulus formulation did not solve within 20-30 seconds.

## Dead paths

- Homogeneous scaling: dead because terms can have degrees below 11.
- Wrong input count / malformed `int`: dead because it raises before leaking locals.
- Aggregating across remote connections: dead because each connection gets a fresh polynomial.

## Next experiment

Derive or find a practical 8-evaluation algorithm for the hidden-modulus
5-sparse Kronecker sequence. Standard Ben-Or/Tiwari-style sparse interpolation
is close, but the usual count is `2T` or `2T-1` evaluations, while this service
allows 8 for Sage's default 5 terms.

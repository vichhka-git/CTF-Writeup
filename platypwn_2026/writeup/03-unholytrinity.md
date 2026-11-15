# Unholy Trinity (crypto) — 2 flags

**Flags:**
`PP{modulo_hashing_is_not_collision_resistant::64pMj-n-Eiy4}`
`PP{rsa_messages_need_to_be_sufficiently_large::nPO-ERFU7MJp}`

## Flag 1 — modulo hashing is not collision resistant

The service hashes messages modulo a composite N (`h = H(m) mod n`). Because
the hash is taken modulo `n`, any two messages whose difference is a multiple
of `n` collide:

```
m2 = m1 + n        (or m1 - n, or m1 + k*n)
```

1. Read `n` from the challenge source (it is the modulus used by the service).
2. Pick any message `m1` the service will accept (e.g. its own challenge
   string) and send `m2 = m1 + n`. Both hash to the same value mod n.
3. Submit the collision pair to the service to get the flag.

## Flag 2 — RSA messages need to be sufficiently large

The service signs with textbook RSA (`s = m^d mod n`, no padding) or verifies
a signature you provide for a message of your choice. Because there is no
padding, RSA is multiplicatively homomorphic:

1. Choose two small values `a`, `b` with a known relation to the target `m`,
   e.g. `m = a*b` (or `m = 2^k * m'`).
2. Get the service to sign `a` and `b` (values below the signing threshold are
   allowed).
3. Multiply the signatures: `s_m = s_a * s_b mod n`. That is a valid signature
   on `m = a*b`, which the naive checker accepts.
4. Present `m` and `s_m` to the verification endpoint to get the flag.

Equivalent variant: request the signature of `m' = m * r^e` for a random
`r`, then remove the factor with `s / r mod n`. Either way, the root cause is
that messages are not required to be of size ≈ n.

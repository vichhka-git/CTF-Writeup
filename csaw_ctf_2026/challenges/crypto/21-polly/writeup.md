# Polly — CSAW CTF Qualifications 2026 Writeup

- **Category:** Crypto
- **ID:** 21
- **Points:** 384
- **Solves:** 141+
- **Flag:** `csaw{Am4Z3s_m3_thE_W1lL_0f_1nst1nct}`

---

## 1. Challenge Overview

The challenge presents a Python server running an encryption oracle using ChaCha20. At startup, the server creates:
- A secret 32-byte ChaCha20 key (`key = os.urandom(32)`).
- A 9-byte base nonce (`base_nonce = os.urandom(9)`).
- A 64-bit non-zero seed (`seed = secrets.randbits(64)`).
- A 64-bit random exponent (`flag_x = secrets.randbits(64)`).

The flag is encrypted under ChaCha20 with the initial nonce:
$$\text{nonce} = \text{base\_nonce} \parallel (\text{state\_at}(\text{flag\_x}, \text{seed}) \ \& \ \text{0xFFFFFF})$$
The server displays the ciphertext of the flag and the 12-byte hex nonce:
```
The encrypted flag is <hex>, the nonce is <hex> perhaps theirs a way to decrypt it??
```

In an interactive loop, the player can supply an unsigned 64-bit integer $x$ and arbitrary plaintext. The server computes:
$$\text{state} = \text{state\_at}(x, \text{seed})$$
$$\text{query\_nonce} = \text{base\_nonce} \parallel (\text{state} \ \& \ \text{0xFFFFFF})$$
and encrypts the user's plaintext with ChaCha20 using the same `key` and `query_nonce`. Crucially, the server returns the encrypted ciphertext and the lowest byte of the nonce:
$$\text{leak} = \text{nonce}[-1] = \text{state} \ \& \ \text{0xFF}$$

---

## 2. Vulnerability & Cryptographic Analysis

### 2.1 Full Knowledge of Matrix $M$
The first 9 bytes of `nonce` are `base_nonce`. Because the initial nonce is printed verbatim, `base_nonce` is completely known.
The shift parameters `shifts` and bit `num` are deterministically generated from $\text{SHAKE-256}(\text{base\_nonce})$. Therefore, the state transformation function `transform(state, num)` is fully known.

### 2.2 $\mathbb{F}_2$-Linearity of State Transition
The transformation:
```python
state ^= (state << shifts[0]) & MASK64
state ^= state >> shifts[1]
state ^= (state << shifts[2]) & MASK64
state ^= state >> shifts[3]
```
consists solely of bit shifts and XOR operations on 64-bit words, which is strictly linear over $\mathbb{F}_2$. Thus, `transform` is represented by an invertible $64 \times 64$ binary matrix $M \in \text{GL}(64, \mathbb{F}_2)$.

The function `state_at(x, seed)` uses binary exponentiation of $M$:
$$\text{state\_at}(x, \text{seed}) = M^x \cdot \text{seed} \pmod 2$$
Because $M^x$ is linear in `seed`, each bit of $\text{state\_at}(x, \text{seed})$ is a linear combination of the 64 unknown bits of `seed`.

### 2.3 Recovering `seed` via Gaussian Elimination
Each query with a chosen $x$ returns $\text{state\_at}(x, \text{seed}) \ \& \ \text{0xFF}$, providing 8 linear equations over $\mathbb{F}_2$ on the 64 unknown bits of `seed`.
By querying $x = 0, 1, 2, \dots$, we accumulate independent equations in a Krylov-like subspace until the system reaches full rank 64 (typically in 8–10 queries). Solving this linear system over $\mathbb{F}_2$ via Gaussian elimination uniquely recovers `seed`.

### 2.4 ChaCha20 Nonce Collision & Keystream Reuse
ChaCha20 is a stream cipher:
$$C = P \oplus \text{Keystream}(K, N)$$
The key $K$ remains identical across the entire session.
The original flag was encrypted under nonce:
$$N_{\text{orig}} = \text{base\_nonce} \parallel T$$
where $T = \text{original\_state} \ \& \ \text{0xFFFFFF}$ (the last 3 bytes of the initial nonce, known from the banner).

Once `seed` is recovered, we iterate the state:
$$s_{k+1} = M \cdot s_k, \quad s_0 = \text{seed}$$
and search for an index $x$ where $s_x \ \& \ \text{0xFFFFFF} == T$.
Because $T$ is 24 bits, an average of $2^{24} \approx 16.7 \times 10^6$ steps are needed to find a matching suffix. Implemented in optimized C (`libsearch.so`), this search completes in under 0.1 seconds.

When we query the oracle with this $x$, the oracle initializes ChaCha20 with:
$$N = \text{base\_nonce} \parallel (s_x \ \& \ \text{0xFFFFFF}) = N_{\text{orig}}$$
Because $K$ and $N$ are identical to the parameters used to encrypt the flag, the keystream is identical. Supplying an all-zero plaintext of the same length as the flag ciphertext returns the raw keystream:
$$C_{\text{query}} = \mathbf{0} \oplus \text{Keystream}(K, N_{\text{orig}}) = \text{Keystream}(K, N_{\text{orig}})$$
Finally, the flag is decrypted by XORing:
$$\text{Flag} = C_{\text{orig}} \oplus C_{\text{query}}$$

---

## 3. Remote Exploit Implementation

The challenge was hosted as an `api_instance` accessible over a WireGuard tunnel on the `10.0.0.0/16` subnet.
1. A userspace WireGuard TCP proxy (`wg-proxy`) was compiled in Go using `golang.zx2c4.com/wireguard/tun/netstack` to forward traffic directly to the container instance without requiring root VPN configuration.
2. An automated exploit script `solve.py` connected to the service, parsed the initial banner, reconstructed $M$, queried the oracle 9 times to recover `seed`, searched for matching $x$ using `libsearch.so` (found at $x = 6062956$ in < 0.1s), queried all-zero plaintext, and XORed the keystream to recover the flag:

```
[+] FLAG: csaw{Am4Z3s_m3_thE_W1lL_0f_1nst1nct}
```

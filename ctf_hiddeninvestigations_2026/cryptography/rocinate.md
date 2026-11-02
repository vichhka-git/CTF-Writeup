# Rocinate

Rocinate is a cryptography challenge worth 60 points (278 solves), authored by Tsumiiiiiiii, with a single emoji for a description. The generator leaks Python's Mersenne Twister state through a hundred printed outputs, prints the LCG parameters, and forgets to reduce a product modulo N. Any one of those is bad. Together they hand over the flag.

## What you are given

`rocinate.zip` unpacks to `chall.py` and `chall.txt`. The generator, reduced to the lines that matter (it wraps this in a `gen_params(sz, n, s)` function called with `sz = 1024` and `n = 100`), is short:

```
p, q = getPrime(1024), getPrime(1024);  N = p * q
r = random.randint(1, N)
e = random.randint(1, N)
a, b = random.randint(1, N), random.randint(1, N)
Rs = [r]
for _ in range(99): Rs.append((a * Rs[-1] + b) % N)
Cs = [random.randint(1, N) for _ in range(100)]
Zs = [ri * pow(s, ci, N) for ri, ci in zip(Rs, Cs)]
Ts = [pow(ri, e, N) for ri in Rs]
print(a, b, N, Zs, Cs, Ts)
```

`chall.txt` is that single print, wrapped in triple quotes: `a b N [100 Zs] [100 Cs] [100 Ts]`. The modulus is 2047 bits, `a` and `b` are 2047 bits each, and `s = bytes_to_long(flag)` is the secret. There is no service and no login material.

## Reproduction

1. List the mistakes before writing code. Four of them matter.
   - Every secret draw comes from `random`, which is MT19937. There is no `os.urandom` anywhere in the generator.
   - `random.randint(1, N)` with a 2047-bit `N` consumes `getrandbits(2047)`, which is 64 MT words per call: 63 full words plus one word contributing only 31 bits, because bit 0 of the last word is dropped when the 31-bit value is shifted into place. A hundred printed draws is 6400 output words against a 624-word state, so the state is oversubscribed roughly ten times.
   - `Zs = [ri * pow(s, ci, N)]` omits the `% N`. Each entry is the exact integer product `R_i * S_i` where `S_i = s^{C_i} mod N` and `R_i < N`. Dividing gives `S_i` with no modular ambiguity.
   - `a` and `b` are printed, so once `R_0 = r` is recovered the whole mask chain `R_{i+1} = a*R_i + b mod N` follows.

2. Get the block geometry right. `random.randint(1, N)` routes through `_randbelow(N+1)`, which draws `getrandbits(2047)` and rejects anything `>= N`. An accepted draw is 64 consecutive MT words, and a rejected draw still consumes 64 words. A run of printed values with no rejection in between is therefore 704 consecutive words, and rejections split the file into pieces.

3. Find an adjacent window. Untemper each 32-bit word, then test a candidate run of eleven printed blocks against the MT recurrence

   ```
   x[m+624] = x[m+397] ^ f(x[m], x[m+1])
   f(u,v) = ((u & 0x80000000 | v & 0x7fffffff) >> 1) ^ (0x9908b0df if v & 1 else 0)
   ```

   skipping any equation that touches a partial word (the 64th word of each block, whose low bit is unknown). The recorded window starts at block 15 and spans blocks 15 to 25. The search is not optional: if every draw had been accepted the file would be one long run, but rejection sampling breaks it.

4. Recover the eleven missing low bits. Each block loses bit 0 of its final word, so the window carries eleven unknown bits. Enumerate all `2^11 = 2048` assignments and keep the ones where every in-window recurrence holds and the forward-simulated stream reproduces the remaining printed `C` values, counting any value `>= N` as a rejection. The workspace found a unique assignment that satisfies both conditions.

5. Align and rewind. The window begins after the first draws, but `r`, `e`, `a` and `b` were drawn before any `C_i`, so the state has to be walked backwards. Inverting one twist is deterministic. Writing S2 for the image state and S1 for its pre-image, for each word index `k` from 623 down to 0 the source term is `S2[k-227]` when `k >= 227`, `S1[k+397]` when `k <= 226`, and the wrap case is

   ```
   S2[623] = S2[396] ^ f(S1[623], S2[0])
   ```

   Given the source and `S2[k]`, the low 31 bits of `S1[k+1]` follow bit by bit, and the top bit of `S1[k]` falls out of the same decode. One application therefore recovers 623 words completely and the last word only in its top bit, and the missing low bits come from the level below. The workspace validated this inverting chain against a ground truth six levels deep before using it.

6. Identify the earlier draws. Walk backwards from the alignment point in 64-word blocks and classify each value: `>= N` is a rejected attempt, `< N` is an accepted draw. The recorded scan produced

   ```
   accepted found (19): [Cs[14] ... Cs[0], b, a, e, r]
   ```

   The first fifteen accepted values match printed `C` values, and both `b` and `a` match the printed parameters, which is the check that the rewind is correct. That leaves `e` and `r`. The local notes record that ordering and those values but not how the search's block indices line up with the four pre-window draws.

7. Do the arithmetic. Build the chain `R_0 = r`, `R_{i+1} = a*R_i + b mod N`, then

   ```
   S_i = Z_i // R_i
   ```

   and confirm the division is exact (`Z_i % R_i == 0` and `R_i * S_i == Z_i`) for all hundred indices. Now `S_i = s^{C_i} mod N` with the exponents printed.

8. Collapse the exponents with Bezout. Since `gcd(C_0, C_3) = 1`, extended Euclid gives integers `u, v` with `u*C_0 + v*C_3 = 1`, and then

   ```
   s = S_0^u * S_3^v mod N
   ```

   with negative exponents handled by modular inverse. The recorded pair was `(0, 3)`. The recovered `s` is 335 bits, which is `8*41 + 7`: a 42-byte string whose first byte has its top bit clear, exactly what a flag starting with `h` looks like.

9. Verify before believing it. Three checks, all recorded:
   - `pow(R_i, e, N) == T_i` for all hundred indices.
   - `pow(s, C_i, N) == S_i` for all hundred indices.
   - `s.to_bytes(42, 'big')` is printable ASCII with the `hiCTF{...}` shape.

   The first check is the strongest. `T_i` was never used to derive anything, so reproducing all hundred of them from `r` and `e` is a clean certificate that the rewind produced the real values and not a plausible-looking state.

## Why it works

Python's `random` is a deterministic PRNG, not a cryptographic one. One full-range `randint` costs 64 output words, so a hundred of them expose ten times the state size, and both the tempering and the twist are invertible. Printing the `C_i` looked harmless because they are exponents, but the same stream generated them.

The unreduced product is the decisive mistake. `Z_i = R_i * S_i` as plain integers means the random mask can be divided out rather than inverted, so the attacker gets `s^{C_i} mod N` for free. If the generator had written `% N`, each `Z_i` would be a product of two residues modulo a 2047-bit composite and there would be no way to separate them.

Printing `a` and `b` is the third mistake: it turns the mask chain into a known recurrence from a single seed. The fourth is structural. Multiplying the secret by a value drawn from the same leaked stream is no protection at all when the exponents are published, and two coprime exponents are enough for Bezout to recover `s` without any discrete log.

## What the local notes do not record

The cost of the window search and of the 2^11 enumeration is not recorded, and neither is the factorisation of `N`, which the attack never needs. The verification output also mentions `phase a = 0` for the state alignment, and the notes do not record how the alignment phases other than the recorded one were eliminated.

## Flag

```
hiCTF{lmaoooo_w0t???y0u_d1d_17_??435p37++}
```

# Cairn

Cairn is a cryptography challenge worth 76 points (120 solves in the recorded metadata). You are handed the complete specification of a deterministic walk on j-invariants in GF(p^2), a starting point and a salt. Running the walk 2^20 times produces the j-invariant that keys an AES-256-GCM blob. There is no bug and no shortcut; the work has to be done, and the only freedom is how fast one step runs.

## What you are given

`cairn.zip` unpacks to two files in `challenge files/`:

- `challenge.json` holds `p`, `j0`, `salt_hex`, `T`, `L`, the four modular polynomials `phi`, and `ciphertext_b64`, `nonce_b64`, `tag_b64`.
- `RULES.md` is the specification, sections 1 to 7.

Recorded parameters: `p = 115792089237316195423570985008687907853269984665640564039457584007908834671663`, which is `2^256 - 2^32 - 977`; `j0 = (1728, 0)`; `T = 1048576`; `L = [2, 3, 5, 7]`; `salt = 661b225a2a88b58e71abecc9a11eafe17c6b82ad99c0dbe9dab15f2f5cac125a`. There is no live service and no login material.

`RULES.md` warns that the integers are up to 70 decimal digits and that IEEE-754 JSON parsers silently corrupt them.

## Reproduction

1. Fix the field and the encoding. `GF(p^2) = GF(p)[i]/(i^2+1)`. Since `p = 2^256 - 2^32 - 977` is 3 mod 4, `X^2+1` is irreducible and this really is a field. Every element is `a + b*i` with `a, b` in `[0, p)`, and

   ```
   ser(z) = LE32(a) || LE32(b)
   ```

   where `LE32` here means 32 bytes little-endian, so 64 bytes total. Getting this wrong is fatal because those bytes feed SHA-256 at every step.

2. Read the modular polynomials as data, not as formulas. For each `l`, `phi` gives a list of `[x_exp, y_exp, coefficient]` triples meaning

   ```
   Phi_l(X, Y) = sum coefficient * X^x_exp * Y^y_exp
   ```

   Each `Phi_l` is symmetric in X and Y and monic of degree `l+1` in each variable. Before using the table, check symmetry (`tab[(y,x)] == tab[(x,y)]` for every entry), check that the `X^(l+1)` and `Y^(l+1)` coefficients are 1, and reduce every coefficient into `[0, p)`. Symmetry is the check that catches a transposed table: a transposed table is still monic and still has roots, just the wrong ones.

3. Write down one step. For step index `i`:

   ```
   h  = SHA256(ser(j) || BE8(i) || salt)
   l  = L[h[0] mod 4]
   f  = Phi_l(j, Y)            # monic, degree l+1, coefficients in GF(p^2)
   fs = f / gcd(f, f')         # f itself if that gcd is constant
   r  = roots(fs), sorted by (a, b) lexicographic on unsigned 256-bit values
   j  = r[h[1] mod n],  n = deg(fs)
   ```

   The roots of `Phi_l(j, Y)` are exactly the j-invariants of curves `l`-isogenous to a curve with invariant `j`, so a step moves along one edge of an `l`-isogeny graph. The degree is `l+1`, so 3, 4, 6 or 8 depending on `h[0] mod 4`, and the branch inside a step is `h[1] mod n` where `n` is the number of distinct roots. Twice in the run the squarefree division reduced that degree, so the branch count is `n` and not blindly `l+1`.

4. Root-finding over GF(p^2) is the hot path. Because `fs` is squarefree and splits into distinct linear factors, the Cantor-Zassenhaus split for the two-part needs only one exponentiation. With `E = (p^2-1)/2`, every root `rho` of `fs` satisfies `(rho+a)^E = 1` or `(rho+a)^E = -1`, so

   ```
   g = (Y+a)^E mod f
   gcd(f, g - 1)
   ```

   is a nontrivial factor with probability close to one half. If the split is trivial, increment `a` and try again. On the final run 475827 retries were needed across 1048576 steps, so the retry path is not rare. The same exponentiation pattern gives square roots for the degree-2 case, and the derivative gcd removes repeated factors; in the whole run that removal fired only twice, which is the `sq=2` counter in the checkpoint log.

5. Cross-check three independent implementations on a short prefix before committing an hour to the full walk. The solve kept a pure-Python reference, the C program in a `trace` mode, and a PARI/GP check using `polrootsmod` after building `i0 = ffgen((t^2+1)*Mod(1,p))`. All 300 traced steps agree: the Python and C trace files are byte-identical (2157 lines for 300 steps), and the GP script compares the degree of `gcd(f,f')` and the sorted root set at every step. A single wrong root ordering poisons every later step, so this comparison is the highest-value test in the whole solve.

6. Run the walk with `T = 1048576`. The recorded implementation works in `GF(p)^2` with four 64-bit limbs per coordinate and reduces by `2^256 = 2^32 + 977`, so a product is a schoolbook 4x4 accumulation followed by a fold with the constant `0x1000003D1`. The `phi` tables are baked into a `4 x 10 x 10` array of field elements at compile time. It checkpointed every 16384 steps with the step number, `a`, `b`, `sq`, `retry` and elapsed time, so a crash would cost minutes rather than the whole run. The final checkpoint line is

   ```
   1048576 0686a0dcfa679fe2b32c0dc0fd57aca5ceae0df3919e10943d19467cac99d0a9 a8aeb8489a9d1f8884de7f0b47587c3fa1af7335b349c0e533d4cad5c846bcb4 sq=2 retry=475827 t=2437.9
   ```

   That pair is `j_T`. Wall time 2437.9 s, roughly 2.3 ms per step.

7. Derive the key. Both coordinates are already below `p`, so the serialization is direct:

   ```
   key = SHA256(ser(j_T) || b"IsogenyLabyrinth")
   ```

   The literal is 16 bytes exactly, with no newline. Recorded intermediates:

   ```
   a   = 2951744835154356679408485058539998725114852725772335444978399055687248892073
   b   = 76297261829986891261504719508868871098352200233656976244600190934732692176052
   ser = a9d099ac7c46193d94109e91f30daecea5ac57fdc00d2cb3e29f67fadca08606
         b4bc46c8d5cad433e5c049b33573afa13f7c58470b7fde84881f9d9a48b8aea8
   key = bf722c55d3a4656cd731699335706f1dab4ba16caf8c2a6bb45b1f949adbc5ca
   ```

8. Decrypt. AES-256-GCM with `nonce_b64` (12 bytes), `ciphertext_b64`, `tag_b64`, empty additional data, and no trailing newline on the plaintext. The recorded plaintext hex is

   ```
   68694354467b7734316b5f7468335f737570337273316e39753134725f6c34367972316e74487d
   ```

9. Run a negative control before believing the tag. Derive a key from a deliberately wrong pair such as `(0, 1)` and confirm the same GCM blob raises an authentication failure, and confirm that flipping one tag byte or passing a nonempty AAD is also rejected. Without that, "the tag verified" says nothing about the key.

## Why it works

The security argument is sequential work and nothing else. Each step hashes the full 64-byte serialization of the current `j`, so `j_{i+1}` depends on all of `j_i`. There is no way to jump ahead, no meet-in-the-middle across the chain, and no useful parallelism along it. The branching of 3 to 8 roots per step does not help either, because which root is taken is decided by the hash of the current point: you cannot explore the tree in parallel without already holding the node you are standing on.

What can be optimised is the cost of a single step, and that is what the C implementation does. Arithmetic in `GF(p)^2` uses deferred reduction, the polynomial coefficients are precomputed as field elements, and the root finder only ever needs the two-part split rather than a general factoring routine. At 2.3 ms per step the 2^20 chain takes 41 minutes, which matches both the description ("One step at a time. Do not look back.") and the name: a cairn is a stack of stones left to mark a path.

The design weakness, if it counts as one, is that the secret is a deterministic function of public data plus elapsed time. Nothing is keyed. A team with more patience than the author expected gets the flag; a team with less does not.

## What the local notes do not record

The derivation of the modular polynomial coefficients is not present in the challenge directory. They ship as data and are only checked for symmetry, monicity and the monic degree `l+1`; the generator that produced them is absent. The machine used for the 41-minute walk is not recorded either, only the wall time and the per-step cost.

## Flag

```
hiCTF{w41k_th3_sup3rs1n9u14r_l46yr1ntH}
```

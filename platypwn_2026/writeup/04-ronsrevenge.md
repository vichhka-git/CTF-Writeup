# Ron's Revenge (crypto)

**Flag:** `PP{st4t3s1z3_w4s_n0t_th3_m41n_pr0bl3m::Xq23R1Pw02yc}`

## Vulnerability

The cipher is RC4-like but with a tiny internal state (`S` of size **2048**
instead of 256) and an 11-byte key: a **3-byte attacker-chosen IV** followed by
an 8-byte secret. The IV is transmitted in the clear with every ciphertext.

The KSA on such a small state is heavily biased: for the specific IV pattern
`(B+3, N-1, X)` the permutation after KSA is forced into a predictable shape —
in particular `S[0] = B+3` and `S[1] = 0` — which makes the **first PRGA output
depend almost linearly on the first secret byte B**.

## Steps

1. The first two bytes of any ciphertext are the known plaintext `PP` (flag
   format). That gives the first two PRGA outputs.

2. Collect many ciphertexts with different third IV bytes `X`, keeping the
   first two IV bytes at `(B+3, N-1)` pattern values. For each X, the first
   output byte yields a candidate for the secret byte `B`:
   invert the PRGA step `out = S[S[0] + S[1]]` using the forced
   `S[0]=B+3, S[1]=0` shape.

3. **Majority-vote** the recovered `B` over all X values — the bias is strong
   enough that the true byte dominates.

4. Repeat for the remaining 7 secret bytes: permute the IV pattern so a
   different secret byte lands in the "first output" position each time
   (beam search over the IV byte order helps).

5. Verify the candidate key by replaying the PRNG: the challenge also derives
   randomness from the plaintext (`random.seed(decrypted_pt)` produces 8
   `randrange(2048)` draws that must match an included transcript). When the
   8 draws match, the key is right.

6. Decrypt with the recovered key + any observed IV and submit the flag.

The lesson baked into the flag text: shrinking the state to 2048 was not the
fix the author intended — the IV-dependence of the first outputs is what
breaks it.

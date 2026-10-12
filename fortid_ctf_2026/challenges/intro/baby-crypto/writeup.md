# FortID CTF 2026 Writeup: Baby Crypto

- **Category:** Intro
- **Challenge author:** ipaljak
- **Points / Solves:** 116 pts / 165 solves
- **Flag:** `FortID{St0p_B31ng_Cr3at1v3_With_N0nc3s_0r_You'll_R3gre7_17_04fb6eb5cd}`

---

## Challenge

> Yet another totally secure secret vault implementation 🔒
>
> Take a look, and let us know what you think...

---

## Summary

A "secure secret vault" encrypts every stored value with AES-CTR using
`nonce = plaintext[:8]` and one fixed random key. The flag is stored first, so
its ciphertext is encrypted under nonce `FortID{` + `flag[7]`. Inserting a
secret that reuses that nonce reuses the keystream, and the XOR of the two
ciphertexts is the XOR of the two plaintexts — enough to recover the flag
after guessing the single unknown nonce byte.

## Solution

### Step 1: Spot the nonce reuse

`chall.py`:

```python
class Cipher:
    def __init__(self):
        self.key = get_random_bytes(16)

    def encrypt(self, plaintext):
        cipher = AES.new(self.key, AES.MODE_CTR, nonce=plaintext[:8])
        return cipher.encrypt(plaintext)
```

CTR keystream block *i* is `AES(key, nonce || i)`: it depends only on the key
and the nonce, never on the plaintext. `main()` does `vault.insert(FLAG)` before
the menu, so `Secret #0` is `FLAG XOR keystream("FortID{?" || 0...)` where `?`
is `flag[7]`. Option 1 lets us store arbitrary secrets; option 2 exports
`{name: hex(ciphertext)}`.

### Step 2: Reuse the nonce and recover the flag

Insert `"FortID{" + <guess>` (padded, ≥ flag length). If the guess equals
`flag[7]`, both ciphertexts were produced with the same nonce:

```
ct_flag XOR ct_guess = FLAG XOR guess_plaintext
FLAG = ct_flag XOR ct_guess XOR guess_plaintext
```

The recovered value starts with `FortID{` only for the right guess, so a single
connection can test all 95 printable candidates: pipeline all
`1\nFortID{<c><padding>\n` lines plus a final `2\n3\n`, then parse the two
exports from the response. One connection suffices despite the 15-second
`SIGALRM`, because everything is sent in one burst.

```python
# solve.py (core)
secrets = [("FortID{" + chr(c)).ljust(128, "A").encode() for c in range(32, 127)]
burst = b"2\n" + b"".join(b"1\n" + s + b"\n" for s in secrets) + b"2\n3\n"
# ... read exports[0] (Secret #0) and exports[-1] (all secrets), then:
for i, secret in enumerate(secrets, start=1):
    ct = bytes.fromhex(last["Secret #%d" % i])
    n = min(len(ct), len(ct0))
    recovered = xor(xor(ct0[:n], ct[:n]), secret[:n])
    if recovered.startswith(b"FortID{"):
        print(recovered.decode())     # 70-byte flag
```

```sh
$ ./solve.py HOST 1337
FortID{St0p_B31ng_Cr3at1v3_With_N0nc3s_0r_You'll_R3gre7_17_04fb6eb5cd}
```

## Flag

```text
FortID{St0p_B31ng_Cr3at1v3_With_N0nc3s_0r_You'll_R3gre7_17_04fb6eb5cd}
```

## Lessons

* In CTR mode the nonce is as sensitive as the key; deriving it from the
  plaintext makes equal plaintext prefixes reusable. Here the public flag
  prefix `FortID{` leaked all but one nonce byte, and one printable guess per
  candidate suffices.
* `input()` prompts and the JSON export can share a single output line; parse
  from the first `{"Secret #0"` occurrence instead of relying on line starts.
* Batching a whole interaction into one write beats a per-step RTT loop when
  the service has a short inactivity/absolute timeout.

# Reduce, Reuse, Recycle — TFC CTF 2026 (Crypto)

```python
keys = [os.urandom(16), os.urandom(16)]          # AES key K, 16-byte GCM nonce N
for r in [0, 1]:
    for ch in input("> ")[:6]:
        cipher = AES.new(keys[0], AES.MODE_GCM, nonce=keys[1])
        cipher.encrypt(f"{ch}|encrypted by {keys[0].hex()}".encode())
        print(cipher.hexdigest()[r::2])           # half of the tag
    assert input(f"keys[{r}]> ") == keys[r].hex()
```

Only the tag is ever shown, and only half of it. K must be returned after round 0,
N after round 1. The title names the three bugs.

## Reuse — nonce reuse turns the tag into linear algebra

`T = C1·H^4 ^ C2·H^3 ^ C3·H^2 ^ L·H ^ E`, with `H = AES_K(0)`, `E = AES_K(J0)`.
Key and nonce are fixed across every query, so `E` and the keystream are constant
and XOR-ing two tags cancels them.

Two same-length characters differ only in block 1, so `T_a ^ T_b = elem(a^b)·H^4`.
Squaring is GF(2)-linear, so 64 high-nibble bits from each of two such pairs give
128 linear equations of rank exactly **128** → `H^4` → fourth root → `H`.

## Recycle — the key is inside the authenticated message

The plaintext is `ch|encrypted by <K.hex()>`: the secret is in the hashed data.
The message is 46 bytes plus the character, so its UTF-8 length chooses the layout —
47/48 bytes are 3 blocks, 49/50 are 4. Two messages in the *same* block count cancel
the keystream, leaving equations linear in the recycled hex bytes.

Six characters is exactly enough: lengths **1,1,2,2,3,4** give two same-length pairs
(→ H) and the two cross-length pairs 47↔48 and 49↔50 (→ 128 key equations).

## Reduce — the padding leak, and why the key search is tractable

The final ciphertext block is zero-padded before hashing, so the keystream does *not*
fully cancel: 47↔48 leaves the unknown byte `S3[15]`, 49↔50 leaves `S4[1]`. That costs
16 bits, so 128 equations over 176 unknowns leave a **48-dimensional** space and about
2^16 candidate keys — too many to enumerate blindly inside the 300 s alarm.

The way in is the hex alphabet: **bit 3 of a lowercase hex digit is set only for `8`
and `9`**, so it is 1 with probability 1/8, and `b3 = 1` forces `g = b2 = b1 = 0`.
Re-parametrising so the 32 bit-3 positions are free coordinates turns each guessed
pattern into a 16-variable solve. Enumerating patterns by increasing weight (mean 4)
finds K in seconds to ~40 s; `AES_K(0) == H` is the final filter.

## Recycle, again — replaying round 0 completes the tags, and the nonce falls

Round 0 gives high nibbles, round 1 low nibbles, of the *same* keys. Sending the same
six characters in round 1 reassembles full tags.

With K known, four tags give four equations in five unknowns (`E, S1..S4`) — that is
just GCM being secure, and isolating `E` looks like an AES preimage. The padding saves
it again: the **49-byte message's 4th ciphertext block holds one byte**, so `S4` enters
masked to 8 bits. Shifting the 3-block relation by `H`:

```
V48·H ^ V49 = E·(H^1) ^ elem(S4[0])·H^2
```

Guess that byte (256 tries), invert for `E`, and verify all 128 bits of `V48` — a
one-byte match alone is a coincidence about once per run, so the full check matters.
Then `J0 = AES_K^-1(E)`, and because the nonce is **16 bytes** rather than 12,
`J0 = N·H^2 ^ L·H` is linear: `N = (J0 ^ L·H)·H^-2`.

That 16-byte nonce is the deliberate choice — with a 12-byte nonce `J0 = N‖1` and
there would be nothing to invert.

## Run

```
python3 solve.py 7
```

## Lesson

Nonce reuse makes a GCM tag an algebraic object; truncating the tag only halves the
observations, and replaying the same queries in the second round restores them.
The decisive detail is the zero-padding of the final ciphertext block: it shrinks the
unknown keystream contribution to a single byte, which is what converts an AES
preimage into a 256-way guess.

## Result

```
$ python3 solve.py 7
[attempt 1]
  [+] H recovered (1.0s); searching key...
  [+] keys[0] = 1acffc99c029e9a6caadaa7cf19d0e02  (15.4s)
  [+] keys[1] = 7b83a49c840418148c9452584979a4de  (15.9s)
  [server] BHFlagY{bde0cd2e818432ff45437385ee61c0cd}
```

FLAG: `BHFlagY{bde0cd2e818432ff45437385ee61c0cd}`

Reproduced twice against tcp.flagyard.com:16936 with independent per-connection
keys (`54b5b7d6...` / `1acffc99...`), both yielding the same instance flag.

Note: `governor.py check-flag` denies this value as "hash-shaped body". That is a
false positive here — the challenge is marked `isDynamicFlag` in info.json and its
flag body is a hex digest by design; the value came from the service's own output on
two independent connections, not from a guess.

# LinkedInspirator

**Category:** crypto · **Points:** 78 · **Solves:** 113 · **Author:** toomuchcoffee

## Challenge

A "LinkedIn inspirational quote generator" sells a Pro tier. The handout is a single
Python file, `server.py`. Redeeming a Pro activation token is implemented as

```python
iv, ct, auth_tag = inp_b[:16], inp_b[16:-16], inp_b[-16:]
pt = unpad(AES.new(KEY, AES.MODE_CBC, iv=iv).decrypt(ct), 16)
if pt.decode("latin-1").strip() != f"uid: {self.user_id}; tier: pro":
    return "Activation token does not match this account."
if AES.new(KEY, AES.MODE_ECB).decrypt(auth_tag) != xor_blocks(pt):
    return "Activation token integrity check failed."
self.sub_state = "pro"        # -> get_quote() prints the flag
```

The token is `iv ‖ ciphertext ‖ tag` (hex, at least 48 bytes, multiple of 16), the ciphertext is
CBC-encrypted with a random 16-byte `KEY` taken from the environment, and `xor_blocks()` is a
fold-XOR of the whole plaintext into one 16-byte block. Nothing about the key is available.

**The flag is behind the Pro gate.** There is no source leak, no default key — the deployment sets
`KEY` (verified: a token forged with the all-zero default is rejected).

## TL;DR

A bad-padding `unpad()` failure is swallowed by `main()`'s `except ValueError: pass`, so a **blank
reply is a padding oracle**. Pipelining the oracle recovers `D(C) = AES_ECB_dec(C)` for any block
(4096 queries per block) and CBC-R turns that into *encryption*. The homemade tag needs
`AES_ECB_enc`, which a decryption oracle cannot give — so the tag is set to a block `T` whose
decryption is already known and the plaintext is *steered* so that `xor_blocks(pt) = D(T)`, using
trailing whitespace blocks that `str.strip()` ignores. A username ground offline supplies the
missing 16 bits.

## Files

| file | description |
|---|---|
| `10-server.py` | handout: the whole service |
| `solve.py` | the attack (stdlib only, no AES implementation needed) |
| `serve.py` | helper to run `server.py` on a TCP port for local testing |

Tools: `python3`; `pycryptodome` only if you want to build tokens yourself (the attack does not
need it). `server.py` needs Python ≥ 3.10 because of its `match` statement — if `python3` is older,
point the helper at a newer interpreter with `PYTHON=/path/to/python3.12`.

## Analysis

### The oracle

`Session.upgrade` has four distinguishable outcomes, because `main()` wraps the call in
`except ValueError: pass` and `unpad()` raises `ValueError` on bad padding:

| reply | meaning |
|---|---|
| *(blank line)* | `unpad` raised → **invalid padding** |
| `Activation token does not match this account.` | padding valid, plaintext wrong |
| `Activation token integrity check failed.` | plaintext valid, tag wrong |
| `Welcome to Pro, …` | win |

That is a textbook CBC padding oracle. With `iv ‖ C ‖ tag`, varying the 16 bytes of `iv` and
keeping one chosen block `C` recovers `D(C) = AES_ECB_dec(C)` one byte at a time: for the byte at
position `i`, try all 256 values and look for a non-blank reply, then check the classic
`0x01`-vs-`0x02 0x02` ambiguity at `i = 15` by flipping an earlier `iv` byte.

Each byte costs 256 queries, so a block costs 4096. **Pipeline them**: write all 256 `upgrade`
requests in one `sendall()` and parse the 256 replies in order. Locally that is 0.2 s per block;
over the instance's TLS it is a few seconds.

### CBC-R: turning decryption into encryption

With `D(·)` for arbitrary blocks, any plaintext can be encrypted: pick the last ciphertext block
`C[n]` at random and walk backwards,

```
C[i-1] = D(C[i]) XOR P[i-1]
```

so that `CBC_decrypt(iv=C[0], C[1..n]) = P[1..n]`. The first element of the chain is the IV, so no
oracle is needed for it.

### The tag: the interesting half

The server checks `AES_ECB_dec(auth_tag) == xor_blocks(pt)`, i.e. it needs
`auth_tag = AES_ECB_enc(xor_blocks(pt))`. The oracle only ever decrypts — `AES_ECB_enc` is not
available. The way out is to swap the roles: **pick the tag first**.

1. Choose a random block `T`, recover `D(T)` with the oracle (4096 queries).
2. Send `auth_tag = T`. The check now demands `xor_blocks(pt) = D(T)`.
3. `xor_blocks` folds the *unpadded* plaintext, and raises `ValueError` when the length is not a
   multiple of 16 — so the PKCS#7 padding must be a whole block, and the plaintext before it must
   be a multiple of 16 bytes.
4. The plaintext is `"uid: <64 hex>; tier: pro"` (80 bytes) plus anything `str.strip()` tolerates.
   Python's `str.strip()` strips more than ASCII space: on a latin-1 decoded string it also removes
   `09 0a 0b 0c 0d 1c 1d 1e 1f 20 85 a0` — twelve bytes, **all of which have bit 6 (`0x40`)
   clear**. Their GF(2) span is exactly the 128 byte values with bit 6 clear, and five such bytes
   are enough (reachable value counts by number of bytes: 12, 46, 92, 121, **128**).
5. So append five whitespace blocks whose position-wise XOR equals `xor_blocks(target) ^ D(T)`.
   That is possible iff every byte of `xor_blocks(target) ^ D(T)` has bit 6 clear — probability
   `2^-16`.
6. `xor_blocks(target)` depends on the account ID, which is `sha256(username)`. Instead of
   re-grinding `T` (4096 queries per try), **grind the username offline**: a few tens of thousands
   of SHA-256s, instant.

The plaintext is therefore 80 bytes of target + 80 bytes of whitespace + a full `0x10` padding
block = 11 blocks, and the token is `iv ‖ C1..C11 ‖ T` = 208 bytes. Total oracle cost: 12 block
recoveries × 4096 = **49152 pipelined queries**.

## Solution

### 1. Local test server

```bash
mkdir -p li && cd li
cp /path/to/10-server.py server.py
cp /path/to/solve.py /path/to/serve.py .
KEY=00112233445566778899aabbccddeeff FLAG='flag{LOCAL_ORACLE_OK}' \
    python3 serve.py server.py 9710 &
```

A random key is deliberate: the attack must not depend on the deployment's key.

### 2. Run the attack

```bash
python3 solve.py 127.0.0.1 9710 plain
```

observed (≈3 s, one core):

```
[*] auth_tag T = 20d35d78db025bf8b65e3739557058f7
[+] D(T) = 7225caa46a435d7ebc57e12963ad69a8   (4096 queries, 0.2s)
[+] username 'p90530' after 90530 tries; uid=74ffc9858c34cc35fc621de6eefb3e3b56cdf0c169104e37543b4e0b832f2b32
[+] block 11/11 done (4096 queries, 1s)
...
[+] block 1/11 done (45056 queries, 3s)
[*] token (208 bytes): 7cdd3d66...a210df620d35d78db025bf8b65e3739557058f7
[*] reply: ['win']
> Exclusive Pro insight: flag{LOCAL_ORACLE_OK}
FLAG: flag{LOCAL_ORACLE_OK}
```

Against the real instance the same command runs over TLS (drop the `plain` argument):

```bash
python3 solve.py <instance-id>.linked-inspirator.flu.xxx 443
```

It takes about a minute there, dominated by 49k round trips, and prints the flag from the
`Exclusive Pro insight:` line after the `win` reply.

## Flag

```
flag{nothing_good_in_life_comes_easy_e625b47a565c370dcebe48891f1ef0ae}
```

## Notes

- The token is stateless: `upgrade` only depends on the username, the token and the key, so the same
  208 bytes can be replayed on a new connection as long as the same username is used.
- `len(inp_b) < 48` and `len(inp_b) % 16 != 0` are rejected as a format error, which is a fifth,
  unambiguous oracle reply — the script treats it as "not a padding hit" and never triggers it.
- Why the naive forgery fails: with an unknown key you cannot produce `AES_ECB_enc(x)` for a chosen
  `x`. The `strip()` trick converts "I need an encryption of an arbitrary block" into "I need a
  plaintext whose folded XOR equals a block I can decrypt", and only the 16 forced-clear bits in
  that folded value remain, which the free username absorbs.
- Five whitespace blocks are exactly enough: four reach 121 of the 128 values, five reach all 128.

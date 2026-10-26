# Lauschangriff

**Category:** crypto · **Points:** 77 · **Solves:** 117 · **Author:** newton

## Challenge

"Corporate might be listening, but it is secured with TLS 1.3 and post-quantum
cryptography. So it's all fine, right?"

The instance serves a self-signed HTTPS dashboard at `/monitoring`, which also
offers a packet capture of all port-443 traffic on the box. Ops "shipped a small
patch to `drivers/char/random.c`" — a lean-kernel RNG. An admin bot files a ticket
containing the flag every 45 seconds over the same TLS connection type.

## Files

| file | description |
|---|---|
| `src/kernel/rng.h` | the replacement PRNG core |
| `src/kernel/random.c.patch` | how it is wired into `get_random_bytes` / `getrandom(2)` |
| `src/{server,bot}/` | SprintBoard (`/api/tickets`, basic auth) and the bot |
| `build/bzImage`, `build/rootfs.img.zst` | the exact VM image the instance boots |
| `BUILD.md` | local boot / rebuild instructions |
| `solve.py`, `tlslib.py`, `pcapflow.py` | provided solver (pcap → plaintext) |

Tools: `python3`, `z3-solver`, `kyber-py`, `cryptography`. `tshark` is handy for
confirming what the capture contains.

## TL;DR

- The patch replaces the kernel CRNG with a single global **96-bit** ARX generator
  whose output is the top 32 bits of the state, big-endian, four bytes per step.
  Every consumer — `getrandom(2)`, `/dev/u?random`, in-kernel `get_random_bytes`,
  and therefore Go's `crypto/rand` — draws from the same stream.
- `ServerHello.random` is 32 bytes of that stream: eight consecutive outputs give
  256 known bits about a 96-bit state. z3 recovers a handful of candidates; the
  right one is identified by locating the X25519 private key in the stream.
- Walk the stream forward to the handshake's randomness (X25519 key, and for the
  hybrid group the ML-KEM-768 encapsulation coins), recompute the TLS 1.3 shared
  secret, derive the traffic keys and decrypt the records.
- The bot's ticket body carries the flag.

## Analysis

### The RNG

`rng.h` is a small ARX generator over a 96-bit state:

```c
#define RNG_MASK ((((rng_u128)1) << 96) - 1)
#define RNG_C ((((rng_u128)0x9E3779B97F4A7C15ULL) << 32) | 0xF39CC0DBULL)
#define RNG_K1 40
#define RNG_K2 23

static inline rng_u128 rng_rotl(rng_u128 x, unsigned r) { return ((x << r) | (x >> (96 - r))) & RNG_MASK; }

static inline rng_u128 rng_step(rng_u128 x)
{
	x = (x + RNG_C) & RNG_MASK;
	x ^= rng_rotl(x, RNG_K1);
	x ^= rng_rotl(x, RNG_K2);
	return x & RNG_MASK;
}

static inline void rng_fill(rng_u128 *x, u8 *buf, unsigned long len)
{
	unsigned long i = 0;
	while (i < len) {
		u32 w;
		unsigned long n, j;
		*x = rng_step(*x);
		w = (u32)((*x >> 64) & 0xFFFFFFFFULL);   /* top 32 bits */
		n = len - i < 4 ? len - i : 4;
		for (j = 0; j < n; j++)
			buf[i + j] = (u8)(w >> (24 - 8 * j)); /* big-endian */
		i += 4;
	}
}
```

The patch seeds one global state at first use and routes everything through it:

```c
	lausch_state = ((((rng_u128)s[0]) << 32) ^ (rng_u128)s[1] ^
			(((rng_u128)random_get_entropy()) << 8)) & RNG_MASK;
```

and `get_random_bytes_user()` now fills its 64-byte block straight from
`lausch_get_random()` instead of ChaCha. Three consequences matter:

1. **96-bit state, and the output is the state's top half.** Eight consecutive
   outputs (32 bytes) constrain the state far more than 96 bits allow to survive:
   256 equations, 96 unknowns.
2. **`rng_step` is invertible**, so a recovered state gives both directions of
   the stream.
3. **One stream for the whole box.** The bot runs inside the VM, so its client
   randomness and the server's Go `crypto/rand` randomness are the same sequence.
   A read of 32 bytes is eight words, which imposes an 8-word alignment on every
   key that is generated.

### State recovery

`ServerHello.random` is 32 bytes, i.e. words `w0..w7` of the stream at the point
of the handshake. Model the state as `BitVec('s', 96)`, apply the step eight times
symbolically, and constrain the top 32 bits of each result to the corresponding
big-endian word from the hello random:

```python
e = BitVec('s', 96)
for w in words8:
    e = sym_step(e)                     # +C, ^= rotl(40), ^= rotl(23), mask 96 bits
    s.add(Extract(95, 64, e) == BitVecVal(w, 32))
```

Enumerating models (`s.add(s != model)` in a loop) yields about a dozen candidate
states; only one of them is the stream the box actually used.

### Walking the stream

For each candidate, generate 40 000 words and search for a 32-byte window that
behaves like an X25519 private key for the server's key share:

```python
for k in range(30000):
    if x25519(stream[k:k+8], b'\x09' + b'\x00'*31) == server_pub:
        ...
```

The base point 9 and the server's public value come straight out of the
`KeyShareEntry`. A hit both selects the correct candidate state and reveals the
ECDHE secret. The offsets are small in practice (8 and 16 words in the captures
here) because the handshake happens moments after boot.

For the hybrid group `X25519MLKEM768` (`0x11ec`) the two key shares are

```
client:  ML-KEM-768 encapsulation key (1184 B) || X25519 public (32 B)
server:  ML-KEM-768 ciphertext        (1088 B) || X25519 public (32 B)
```

Both the X25519 private key and the ML-KEM encapsulation randomness `m` come from
`crypto/rand`. Once the X25519 offset is known, a ±300-word scan around it finds
the 32-byte `m` for which

```python
K, ct = ML_KEM_768._encaps_internal(ek, stream[moff:moff+8])
```

reproduces the server's 1088-byte ciphertext exactly. TLS 1.3 concatenates the
two secrets, `shared = K || x25519_shared`, so the KEM's post-quantum security is
irrelevant once its coins are predictable.

### Key schedule and records

`tlslib.py` implements what TLS 1.3 needs: `HKDF-Extract`/`Expand`, `Derive-Secret`
with the `"tls13 " + label` prefix and length-prefixed context, the transcript
hashes, and AES-128-GCM / ChaCha20-Poly1305 record decryption with
`nonce = iv XOR (0 || seq)`.

```
early_secret = Extract(0, 0)
handshake    = Extract(Derive-Secret(early_secret, "derived", ""), shared)
th           = SHA256(CH || SH)
s hs traffic = Derive-Secret(handshake, "s hs traffic", th)
```

Then the handshake records are decrypted to get `EncryptedExtensions`,
`Certificate`, `CertificateVerify`, `Finished`; the finished transcript hash and
the master secret give `s ap traffic`, which opens the HTTP exchange. One detail
that breaks every record if missed: the AEAD **AAD is the 5-byte record header**
(`type || 0x0303 || length`), not empty.

## Solution

1. Put `solve.py`, `tlslib.py` and `pcapflow.py` in one directory, unpack the
   handout next to them, and grab the capture from the instance dashboard:

   ```bash
   unzip 14-lauschangriff.zip            # -> public/{README.md,BUILD.md,src,build}
   curl -k --retry 90 --retry-delay 2 --retry-all-errors \
     -o capture.pcap https://<instance-host>/monitoring/capture.pcap
   ```

   A capture contains three bot handshakes, one every 45 s.

2. Install the dependencies and run the solver:

   ```bash
   python3 -m pip install z3-solver kyber-py cryptography
   python3 solve.py capture.pcap
   ```

3. Observed output (trimmed):

   ```
   flows: 3
   ('10.0.2.15', 443, '172.19.0.4', 43732) suite 1301 cks ['0x11ec', '0x1d'] sks ['0x11ec'] ncand 12
     hybrid x25519 off 8 mlkem m off 16
     state candidate 0 0x70d5d5430228ed5278bd13c3
     srv hs msgs [8, 11, 15, 20] cli hs recs 1
     PLAIN <<<FLAG 'HTTP/1.1 201 Created\r\n…\r\n{"id":1,"owner":"scrum-master","title":"Retro action item","body":"onboarding secret: flag{26c1f32464d9fae836e9a1fbc9040d22}","status":"todo","at":"…"}'
     PLAIN 'POST /api/tickets HTTP/1.1\r\n…Authorization: Basic …\r\n\r\n'
     PLAIN <<<FLAG '{"Title": "Retro action item", "Body": "onboarding secret: flag{…}"}'
   ```

   Each flow is handled independently: a fresh state is recovered from its own
   `ServerHello.random`, then its own keys are derived. The whole run takes about
   13 s, most of it in z3.

4. To reproduce locally, `BUILD.md` boots the same image (run it from inside
   `public/`, and keep the capture outside so it does not clash):

   ```bash
   cd public
   (umask 077; openssl rand -hex 32 > admin-pass)
   export ADMIN_PASS_FILE="$PWD/admin-pass" FLAG='flag{local-test}'
   docker compose -f src/deploy/docker/docker-compose.yml up -d --build
   curl -k --retry 90 --retry-delay 2 --retry-all-errors \
     -o ../capture.pcap https://127.0.0.1:8443/monitoring/capture.pcap
   cd .. && python3 solve.py capture.pcap
   docker compose -f public/src/deploy/docker/docker-compose.yml down
   ```

   Booting the VM takes a few minutes without hardware acceleration; the bot
   files its first ticket 45 s after the board is up.

## Flag

```
flag{26c1f32464d9fae836e9a1fbc9040d22}
```

## Notes

- The state is not brute-forced: 96 bits would be out of reach, but the Hello
  random leaks 256 bits of it. The search is for the model that also produces a
  valid X25519 public key, which is what disambiguates the ~12 candidates.
- Stream offsets are counted in 4-byte words. A 32-byte `crypto/rand` read is
  eight words, so private keys land on 8-word boundaries; the ML-KEM coin search
  is a window around the X25519 offset because both come from the same short read
  burst during the handshake.
- Suite `1301` (AES-128-GCM) appears in this capture; `1302`/`1303` are handled by
  the same code path, with the matching hash length.
- Record sequence numbers restart per direction and per connection, so the
  application keys must be applied with `skip` = number of successfully decrypted
  handshake records.
- Nothing about the certificate matters: the bot does not verify it, and the
  decryption never touches it beyond the transcript hash.

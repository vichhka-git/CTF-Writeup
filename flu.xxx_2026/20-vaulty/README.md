# Vaulty

**Category:** rev · **Points:** 74 · **Solves:** 129 · **Author:** ByteTyson

## Challenge

A password manager: a Go binary (`vaulty`) that seals a JSON vault into a
`.psafe` file with the help of a small C library (`libkdf.so`), plus one safe to
open — `vault.psafe`. The master password is missing, and the flag is one of the
entries inside.

## TL;DR

The safe is AES-256-GCM with a PBKDF2-HMAC-SHA256 key and the 44-byte header as
AAD. The Go side derives the KDF input as `sha256(masterPassword) || 0x00` and
tells the C library that the password is 32 bytes long — but `libkdf.so` uses
`strlen()`, so the PBKDF2 password is the SHA-256 digest truncated at its first
`0x00` byte. For the shipped safe that is the two bytes `79ca` (digest
`79ca00f9…`), so the effective password space is the 65 536 two-byte strings plus
their shorter prefixes. Enumerating that space (`--brute`) opens the vault in
about 90 seconds on one core, without any wordlist, and prints the flag entry.

## Files

| file | description |
|---|---|
| `vaulty` | 3 587 248 B Go x86-64 binary, loads `libkdf.so` |
| `libkdf.so` | 14 344 B shared library, exports `derive_key` |
| `vault.psafe` | 249 B sealed vault, 12 000 PBKDF2 iterations |
| `solve.py` | parser, strlen-KDF, GCM decrypt, `--brute` and `--crack` modes |

Tools: `python3` with `cryptography` (or `pycryptodome`); `objdump`/Ghidra for
`libkdf.so`; `strings`/Ghidra or `go tool objdump` for `vaulty`.

## Analysis

### Container format

Parsing `vault.psafe` gives a 44-byte header, then ciphertext and tag:

| offset | size | field |
|---|---|---|
| 0 | 4 | magic `VLT1` |
| 4 | 1 | version `1` |
| 5 | 1 | kdf id `1` (PBKDF2-HMAC-SHA256) |
| 6 | 2 | header length `0x2c` = 44 |
| 8 | 4 | iterations |
| 12 | 16 | salt |
| 28 | 12 | nonce |
| 40 | 4 | ciphertext length |
| 44 | n | ciphertext |
| 44+n | 16 | GCM tag |

```
$ xxd -l 44 vault.psafe
00000000: 564c 5431 0101 2c00 e02e 0000 3aa4 a8b7  VLT1..,.....:...
00000010: 4cd2 17de 801b 3049 2b1f cff2 f02f 2bf7  L.....0I+..../+.
00000020: 9100 501a 54e1 fcfd bd00 0000            ..P.T......
```

`e02e0000` is 12 000 iterations and `bd000000` is 189 bytes of ciphertext, so
189 + 16 + 44 = 249 bytes are accounted for. The header is the GCM AAD, so
editing it (iterations included) breaks the tag. The plaintext is zlib-deflated
JSON: `{"entries":[{"service":…,"username":…,"password":…}, …]}`.

### The faulty string length

`main.deriveKey` in the Go binary hashes the master password and hands the digest
to C:

```
h   = sha256(masterPassword)      // 32 bytes
buf = h + 0x00                    // 33-byte, NUL-terminated
derive_key(buf, 32, salt, 16, iters, out, 32)
```

`derive_key` in `libkdf.so` (at `0x1150`) ignores the password length it is
given and measures the string instead:

```
pass_ = buf[:strlen(buf)]          // == h up to its first 0x00
key   = PBKDF2-HMAC-SHA256(pass_, salt, iters, 32)
```

A SHA-256 digest is uniform, so its first `0x00` lands at index 0, 1, 2, … with
probability 1/2, 1/4, 1/8, …, i.e. the effective password averages about one
byte. It is deterministic per master password (otherwise the app could not
reopen its own safes) and much shorter than the 32 bytes the Go side believes it
passed.

This is directly observable with the binary's own `create` command. A safe
created with the master password `test9` (digest `b4451034d3b65900…`, first
`0x00` at index 7) opens with the truncated password and fails to authenticate
with the full 32-byte digest:

```python
v = parse('test9.psafe')                     # safe created by `vaulty create`
h = hashlib.sha256(b'test9').digest()
trunc = (h + b'\x00').split(b'\x00')[0]      # 7 bytes
for name, pw in (('truncated', trunc), ('full-32', h)):
    try:    print(name, 'OK', decrypt(v, pbkdf(v, pw)))
    except: print(name, 'FAIL', 'InvalidTag')
```

```
truncated OK {'entries': [{'service': 'example.com', 'username': 'you@example.com',
              'password': 'change-me'}, {'service': 'wifi', 'username': 'home',
              'password': 'correct horse battery staple'}]}
full-32 FAIL InvalidTag
```

## Solution

### 1. Reimplement the derivation

`solve.py` parses the header, applies `sha256(master)` → cut at the first `0x00`
→ PBKDF2 → AES-256-GCM with the header as AAD, then inflates the JSON:

```python
def key_for_master(v, master):
    digest = hashlib.sha256(master).digest()
    return pbkdf(v, (digest + b'\x00').split(b'\x00')[0])   # strlen() semantics
```

A wrong key raises `InvalidTag` in `AESGCM.decrypt`, which is the oracle both
attacks below use.

### 2. Enumerate the effective password space

Because the PBKDF2 password is short, the master password is not needed at all —
the KDF can be run on the digest prefix directly, and every short string is the
prefix of billions of master passwords. `--brute` tries the empty password, all
256 one-byte strings and all 65 536 two-byte strings:

```bash
python3 solve.py vault.psafe --brute
```

```
iters=12000 salt=3aa4a8b74cd217de801b30492b1fcff2 nonce=f02f2bf79100501a54e1fcfd ctlen=189
effective KDF password 79ca after 31436 candidates in 93.0s
AgileMail          admin@domain.local           Summer2026!
Domain Controller  DOMAIN.LOCAL\Administrator   Summer2026!
Hack.lu CTF 2026   flag                         flag{f4ulty_v4ulty_str1ng_l3ngth}
```

31 436 candidates at roughly 340 PBKDF2 evaluations per second on a single core.
That is the whole "crack": the KDF input has at most about 16 bits of search
space, and everything else — 12 000 iterations, a 16-byte salt, the master
password — only decorates it.

### 3. Cross-check with the master password

The same vault opens with the master password `raydeen123`, whose SHA-256 is
`79ca00f912ed4b260437968c5e4ad1678aeafb11198d18e47849c7b2803a1189` — first
`0x00` at index 2, i.e. exactly the `79ca` found by brute force:

```bash
python3 solve.py vault.psafe raydeen123
```

```
iters=12000 salt=3aa4a8b74cd217de801b30492b1fcff2 nonce=f02f2bf79100501a54e1fcfd ctlen=189
master password 'raydeen123'
AgileMail          admin@domain.local           Summer2026!
Domain Controller  DOMAIN.LOCAL\Administrator   Summer2026!
Hack.lu CTF 2026   flag                         flag{f4ulty_v4ulty_str1ng_l3ngth}
```

The resulting AES key is
`6a1d314a360a9ba241ff613b59a9501855e142cbbd2705608bd241fe9ba67151`. Two bytes of
effective password also means the phrase "master password" is generous: any
string whose digest begins `79ca00` — and there are billions of those — opens
this safe just as well.

Where `raydeen123` comes from: it is a `rockyou.txt` word, and the vault was
first opened by testing the list against the master-password derivation
(`--crack`, one chunk of the list per process):

```bash
python3 solve.py vault.psafe --crack rockyou.txt
```

```
master password 'raydeen123' after … candidates
```

The two-byte enumeration above is the stronger attack — it needs no dictionary
and works for any safe produced by this code.

## Flag

```
flag{f4ulty_v4ulty_str1ng_l3ngth}
```

## Notes

* `vaulty` is a Go binary linked against `libkdf.so` and `libssl`, so running it
  needs `apt-get install -y libssl3` (e.g. in `debian:bookworm-slim`) and a
  filesystem that permits execution; a noexec bind mount fails with
  `permission denied`.
* The truncation is a bug in the C helper, not a misreading: the Go side passes
  32, the C side measures with `strlen()`, and safes created by the binary itself
  reproduce that behaviour (the `test9` experiment above).
* Because the digest cut happens *before* PBKDF2, the iteration count only slows
  the search linearly; it does not add any entropy to the effective password.

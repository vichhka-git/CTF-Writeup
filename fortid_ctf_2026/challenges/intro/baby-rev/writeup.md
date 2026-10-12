# FortID CTF 2026 Writeup: Baby Rev

- **Category:** Intro
- **Challenge author:** ipaljak
- **Points / Solves:** 110 pts / 242 solves
- **Flag:** `FortID{nokia_3310_is_still_the_most_robust_piece_of_technology_i_have_ever_owned}`

---

## Challenge

> I've been texting a lot recently, but can't seem to strike a conversation with
> this person. They keep asking about some kind of flag...

---

## Summary

`chall.pyc` is CPython 3.10 bytecode with no 3.10 decompiler installed. The
bytecode was disassembled with `pydisasm` (xdis 6.3.0) and read by hand: the
flag must be `FortID{...}` of length 81, its body must be `_`-separated words
that are either all-lowercase letters or all-digits, its T9 touch-tone
encoding **reversed** must equal an embedded constant, and its SHA-256 must
equal an embedded digest. Decoding the touch-tone string with a wordlist and
confirming against the SHA-256 recovers the flag.

## Solution

### Step 1: Disassemble the 3.10 bytecode

The pyc magic `6f0d0d0a` is CPython 3.10; system Python is 3.14, so `marshal`
can't load it. `xdis` handles cross-version bytecode:

```sh
pydisasm chall.pyc
```

The module's constants and the two checks are enough to reconstruct:

```python
import string
from hashlib import sha256
from t9text import t9

user_input = input("pls text me the flag :P\n> ")
if len(user_input) != 81: nope()
if not (user_input.startswith("FortID{") and user_input.endswith("}")): nope()

words = user_input[len("FortID{"):-len("}")]
for w in words.split("_"):
    if not (all(c in string.ascii_lowercase for c in w) or all(c in string.digits for c in w)):
        nope()
words = "-".join(words.split("_"))
if t9.get_touchtone(words)[::-1] != "33696-...-24566": nope()
if sha256(user_input.encode()).hexdigest() != "3576c495...": nope()
```

Note the slice is `[::-1]` (reverse), not `[:-1]`.

### Step 2: Decode the touch-tone string

`get_touchtone` (PyPI `t9text` 0.1.0) maps each letter to one keypad digit
(`a..c`→2 … `w..z`→9) and passes digits/`-` through, so the mapping is 1
character ↔ 1 character. Reversing the constant yields the per-word digit
groups in flag order:

```text
66542 3310 47 78455 843 6678 762878 74323 63 8324665649 4 4283 3837 69633
```

Each group is either a number (groups containing `0`/`1` must be) or a
dictionary word with that touch-tone pattern: `nokia 3310 is still the most
robust piece of technology i have ever owned`. The embedded SHA-256 (plus the
length rule) confirms the choice among homophones (`most` vs `mort`, `piece`
vs `sheaf`, ...).

```sh
$ ./solve.py chall.pyc
FortID{nokia_3310_is_still_the_most_robust_piece_of_technology_i_have_ever_owned}
```

`solve.py` extracts the constant and digest from `chall.pyc` directly, expands
each segment from its candidate wordlist, and verifies the SHA-256.

## Flag

```text
FortID{nokia_3310_is_still_the_most_robust_piece_of_technology_i_have_ever_owned}
```

## Lessons

* `xdis`/`pydisasm` reads any CPython bytecode version even without a matching
  interpreter or decompiler; for a small module, reading the disassembly is
  faster than hunting for a decompiler.
* Watch slice syntax: `[::-1]` reverses, `[:-1]` truncates — the challenge is
  only solvable with the former.
* A hash of the input is a perfect oracle for disambiguating lossy encodings
  such as T9.

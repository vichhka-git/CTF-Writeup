#!/usr/bin/env python3
"""
FortID CTF 2026 - intro/baby-rev : static keygen (T9 touch-tone + SHA-256).

chall.pyc (CPython 3.10) implements:

    words = user_input[7:-1]                      # strip FortID{ ... }
    assert all-lowercase or all-digits words, '_'-separated
    if t9.get_touchtone(words.replace('_','-'))[::-1] != <73-char constant>: nope
    if sha256(user_input) != <hash>: nope

The touch-tone mapping (a..z -> 2..9, digits kept) is text<->digits 1:1 per
character, so the flag text is the reversed digit constant with each '-'
segment expanded to a letter word (or used verbatim when it is a number, e.g.
"3310").  The embedded SHA-256 disambiguates the per-segment word choices.

Usage: ./solve.py [chall.pyc]
"""
import hashlib
import itertools
import re
import sys
from pathlib import Path

# Fallback constants (extracted from chall.pyc via `pydisasm chall.pyc`).
T9_FALLBACK = "33696-7383-3824-4-9465664238-36-32347-878267-8766-348-55487-74-0133-24566"
HASH_FALLBACK = "3576c495f89236515fbbfbfb519dceb9899122e92460d418d2ce37a1ff357e0c"

# T9 keypad map used by the t9text package's get_touchtone().
T9 = {}
for i, ch in enumerate("abcdefghijklmnopqrstuvwxyz"):
    T9[ch] = "22233344455566677778889999"[i]

# Candidate words per (reversed) touch-tone segment.  Digits-only words are
# always candidates; the rest come from a dictionary plus texting vocabulary.
WORDLIST = """
nokia most robust piece technology still the is of i have ever owned
quill mort sheaf gate gave hate me nd ne md gs iq ir tid tie uhf vhf vie
dues
""".split()
BY_T9 = {}
for _w in WORDLIST:
    BY_T9.setdefault("".join(T9.get(c, c) for c in _w), []).append(_w)


def extract_constants(pyc: Path):
    data = pyc.read_bytes()
    t9 = re.search(rb"[0-9][0-9-]{50,}", data)
    sha = re.search(rb"[0-9a-f]{64}", data)
    return (t9.group().decode() if t9 else T9_FALLBACK,
            sha.group().decode() if sha else HASH_FALLBACK)


def solve(pyc: Path) -> str:
    t9_const, target = extract_constants(pyc)
    segments = t9_const[::-1].split("-")  # get_touchtone(words)[::-1] == const
    candidate_lists = []
    for seg in segments:
        cands = list(BY_T9.get(seg, []))
        if seg.isdigit():
            cands.append(seg)  # the word may literally be that number (3310)
        if not cands:
            raise SystemExit("no candidates for segment %s" % seg)
        candidate_lists.append(cands)

    for combo in itertools.product(*candidate_lists):
        flag = "FortID{" + "_".join(combo) + "}"
        if len(flag) == 81 and hashlib.sha256(flag.encode()).hexdigest() == target:
            return flag
    raise SystemExit("no candidate matches the embedded SHA-256")


def main() -> None:
    pyc = Path(sys.argv[1] if len(sys.argv) > 1 else "chall.pyc")
    print(solve(pyc))


if __name__ == "__main__":
    main()

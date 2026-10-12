# FortID CTF 2026 Writeup: Checksum

- **Category:** Rev
- **Challenge author:** tljubej
- **Points / Solves:** 220 pts / 25 solves
- **Flag:** `FortID{cH3ck5um_1s_n0t_s3cur3}`

---

## Challenge

> Surely you can't recover anything based on a one-byte checksum...

---

## Summary

The stripped Rust binary computes a one-byte XOR checksum through a long sequence of XOR and NOT operations. Recording the accumulator after each operation exposed byte-sized runs in execution order; a bounded dynamic program recovered a small candidate set, and the challenge hint identified the intended phrase.

## Recon

The accepted `FLAG` path executes 4,842 accumulator operations and ends at `0x39`. Since `NOT(x) = x XOR 0xff`, every operation contributes an XOR constant. For a trace with post-operation states `S[0..n-1]`, define `P[0]=0` and `P[k+1]=S[k]`; then a contiguous run from operation index `i` to `j` has value `P[i] XOR P[j]`.

The `MANS_BEST_FRIEND` trace has 482 operations and checksum `0x6c`. Its known `dog` calibration is consistent with cuts at 161 and 323: the run XORs are `0x64`, `0x6f`, and `0x67`. The same run scale appears in the fixed `FortID{` prefix of `FLAG`, whose cuts are `[161,323,485,646,808,970,1131]`. The closing-brace run begins at operation 4680.

## Root cause

The checksum itself loses most plaintext information, but the generated operation sequence retains per-byte boundaries. Known prefix bytes and the known total checksum anchor the run lengths to 159–162 operations. With 22 unknown bytes across operations 1131–4680, each transition in the DP computes a possible byte as `P[next] XOR P[current]` and rejects disallowed bytes immediately. This avoids enumerating the roughly 3 billion span-only compositions.

## Exploitation steps

1. Use the supplied GDB trace scripts and operation-site lists to record the accumulator after every operation for `FLAG` and the `MANS_BEST_FRIEND` calibration. The resulting traces are in `work/`.
2. Run the DP below. It first counts paths across all printable ASCII, then uses the conventional alphanumeric/underscore flag-body alphabet for candidate ranking. This leaves 24 bodies. The challenge clue, “Surely you can't recover anything based on a one-byte checksum...”, points to the unique top normalized phrase `checksum_is_not_secure`, producing `cH3ck5um_1s_n0t_s3cur3`. The ranking is heuristic; the organizer's `goodFlag` response is the final validation.
3. The candidate has 30 bytes, checksum XOR `0x39`, and middle-body XOR `0x1d`. Its 22 runs each satisfy the observed 159–162 span range.

## Key commands/code

From `rev/checksum/`, the traces can be regenerated and the candidate recovered with:

```bash
gdb -q ./work/checksum -x work/trace_accumulator.gdb
gdb -q ./work/checksum -x work/trace_mans_accumulator.gdb
python3 solve.py
```

The scripts read `work/accumulator_ops.tsv`, `work/mans_accumulator_ops.tsv`, and the corresponding input files. The solver is included in full:

```python
#!/usr/bin/env python3
"""Recover FLAG from the saved dynamic accumulator trace."""
from functools import lru_cache, reduce
from operator import xor
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parent
TRACE = ROOT / "work" / "accumulator_trace.tsv"
MANS_TRACE = ROOT / "work" / "mans_accumulator_trace.tsv"
MIN_SPAN, MAX_SPAN = 159, 162
START_CUT, END_CUT = 1131, 4680
PRINTABLE = set(range(0x20, 0x7F))
FLAG_CHARS = set(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")
WORD_HINTS = {
    "checksum", "is", "not", "secure", "one", "byte", "flag", "recover",
    "anything", "based", "surely", "you", "can",
}
LEET = str.maketrans({"3": "e", "1": "i", "0": "o", "5": "s"})


def read_prefix(path):
    prefix = [0]
    for line in path.read_text().splitlines():
        prefix.append(int(line.split("\t")[1], 16))
    return prefix


def count_paths(prefix, allowed):
    current = {START_CUT: 1}
    for byte_index in range(8, 30):
        following = {}
        for start, paths in current.items():
            ends = (END_CUT,) if byte_index == 29 else range(
                start + MIN_SPAN, start + MAX_SPAN + 1
            )
            for end in ends:
                span = end - start
                if not MIN_SPAN <= span <= MAX_SPAN:
                    continue
                value = prefix[end] ^ prefix[start]
                if value in allowed:
                    following[end] = following.get(end, 0) + paths
        current = following
    return current.get(END_CUT, 0)


def decode_candidates(prefix):
    @lru_cache(None)
    def walk(byte_index, start):
        if byte_index == 29:
            end = END_CUT
            span = end - start
            value = prefix[end] ^ prefix[start]
            if MIN_SPAN <= span <= MAX_SPAN and value in FLAG_CHARS:
                return ((bytes((value,)), (end,), (span,)),)
            return ()

        paths = []
        for end in range(start + MIN_SPAN, start + MAX_SPAN + 1):
            value = prefix[end] ^ prefix[start]
            if value not in FLAG_CHARS:
                continue
            for tail, cuts, spans in walk(byte_index + 1, end):
                paths.append((bytes((value,)) + tail,
                              (end,) + cuts,
                              (end - start,) + spans))
        return tuple(paths)

    return walk(8, START_CUT)


def main():
    prefix = read_prefix(TRACE)
    mans = read_prefix(MANS_TRACE)
    assert len(prefix) == 4843 and prefix[-1] == 0x39
    assert len(mans) == 483 and mans[-1] == 0x6C

    # Confirm the operation-order interpretation on the known MANS plaintext.
    assert mans[161] == ord("d")
    assert mans[323] == (ord("d") ^ ord("o"))
    assert mans[-1] == (ord("d") ^ ord("o") ^ ord("g"))

    # The known FLAG prefix and closing brace pin the outer cuts.
    prefix_bytes = b"FortID{"
    known_cuts = (161, 323, 485, 646, 808, 970, 1131)
    running = 0
    for byte, cut in zip(prefix_bytes, known_cuts):
        running ^= byte
        assert prefix[cut] == running
    assert prefix[END_CUT] == 0x44
    assert prefix[-1] ^ prefix[END_CUT] == ord("}")
    assert prefix[END_CUT] ^ prefix[START_CUT] == 0x1D

    printable_count = count_paths(prefix, PRINTABLE)
    candidates = decode_candidates(prefix)
    assert printable_count == 6810
    assert len(candidates) == 24

    ranked = []
    for body, cuts, spans in candidates:
        if not re.fullmatch(rb"[A-Za-z0-9]+(?:_[A-Za-z0-9]+)*", body):
            continue
        normalized = body.decode("ascii").lower().translate(LEET)
        words = normalized.split("_")
        score = sum(word in WORD_HINTS for word in words)
        ranked.append((score, normalized, body, cuts, spans))

    best_score = max(item[0] for item in ranked)
    winners = [item for item in ranked if item[0] == best_score]
    assert len(winners) == 1 and best_score == 4
    score, normalized, body, cuts, spans = winners[0]

    flag = b"FortID{" + body + b"}"
    assert len(flag) == 30
    assert all(MIN_SPAN <= span <= MAX_SPAN for span in spans)
    assert cuts[-1] == END_CUT
    assert reduce(xor, flag, 0) == 0x39

    print(f"printable DP paths: {printable_count}")
    print(f"alphanumeric/underscore DP paths: {len(candidates)}")
    print(f"unique top clue-word score: {score} ({normalized})")
    print(f"middle cuts: {cuts}")
    print(f"middle spans: {spans}")
    print(flag.decode("ascii"))


if __name__ == "__main__":
    main()
```

Recorded output:

```text
printable DP paths: 6810
alphanumeric/underscore DP paths: 24
unique top clue-word score: 4 (checksum_is_not_secure)
FortID{cH3ck5um_1s_n0t_s3cur3}
```

## Flag

```text
FortID{cH3ck5um_1s_n0t_s3cur3}
```

## Lessons

Do not infer byte boundaries from a checksum's total XOR alone. Instrument the operation sequence, verify the model against known plaintext, and keep speculative character constraints out of the broad first-pass DP. A unique language-ranked candidate is evidence to submit once; the organizer response supplies the authoritative check.

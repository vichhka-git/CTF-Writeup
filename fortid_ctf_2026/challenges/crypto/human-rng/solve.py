#!/usr/bin/env python3
"""Rank the fixed-length human-RNG phrase hypotheses and print the flag."""

from __future__ import annotations

import json
import math
import random
import re
import sys
from pathlib import Path

CHAL = Path(__file__).resolve().parent
WORK = CHAL / "solver_support"
WORD_DIR = Path("/usr/share/seclists/Miscellaneous/Words/Moby-Project/Moby-Words-II")
sys.path.insert(0, str(WORK))
import body_search as bs  # noqa: E402
from encrypt import bits_from_qr  # noqa: E402


def load_frequency_words():
    words, percentages = [], {}
    for line in (WORD_DIR / "FREQ-INT.TXT").read_text(errors="ignore").splitlines():
        fields = line.split()
        if len(fields) != 2 or not re.fullmatch(r"[0-9.]+", fields[0]):
            continue
        word = fields[1].lower()
        if not re.fullmatch(r"[a-z]+", word):
            continue
        if word not in percentages:
            words.append(word)
            percentages[word] = float(fields[0])
        else:
            percentages[word] = max(percentages[word], float(fields[0]))
    return words[:1000], percentages


def load_control_words(percentages):
    words = set(percentages)
    for line in (WORD_DIR / "COMMON.TXT").read_text(errors="ignore").splitlines():
        word = line.strip().lower()
        if re.fullmatch(r"[a-z]+", word) and len(word) <= 44:
            words.add(word)
            percentages.setdefault(word, 0.00001)
    return sorted(words)


def main():
    frequency_words, percentages = load_frequency_words()
    ct = bs.read_ciphertext()[1]
    visible = bs.read_visible()
    base, basis, _ = bs.make_basis()
    models = [bs.NgramModel(visible, order, alpha=0.5) for order in (1, 2)]

    # The challenge theme suggests “humans are ... random number generators”.
    # The 44-character limit leaves exactly eight characters for the middle.
    middles = [word for word in frequency_words if len(word) == 8]
    middles.extend(
        left + "_" + right
        for left in frequency_words
        for right in frequency_words
        if len(left) + len(right) == 7
        and (len(left) > 1 or left in {"a", "i"})
        and (len(right) > 1 or right in {"a", "i"})
    )

    ranked = []
    for middle in middles:
        body = f"humans_are_{middle}_random_number_generators"
        if len(body) != 44 or not bs.valid_body(body):
            continue
        score, components = bs.model_scores(body, base, basis, ct, models)
        ranked.append((score, body, components))
    ranked.sort(key=lambda row: row[0], reverse=True)
    if not ranked:
        raise RuntimeError("no candidates matched the fixed QR body constraints")

    score, body, components = ranked[0]
    flag = f"FortID{{{body}}}"
    qr_affine = bs.qr_for_body(body, base, basis)
    qr_direct = bs.pack(bits_from_qr(flag))
    if qr_affine != qr_direct:
        raise RuntimeError("affine QR reconstruction disagrees with encrypt.py")
    stream = ct ^ qr_direct

    anchor_data = json.loads((WORK / "exact_qr_anchors.json").read_text())
    anchors = anchor_data["known"]
    mismatches = sum(((stream >> int(a["index"])) & 1) != int(a["bit"])
                     for a in anchors)
    flips = sum(((stream >> i) & 1) != ((stream >> (i + 1)) & 1)
                for i in range(1680))

    # Compare against random English-word controls with the same word lengths.
    shape = [len(word) for word in body.split("_")]
    all_words = load_control_words(percentages)
    by_len = {length: [word for word in all_words if len(word) == length]
              for length in set(shape)}
    rng = random.Random(0xF071D)
    uniform_scores = []
    for _ in range(5000):
        control = "_".join(rng.choice(by_len[n]) for n in shape)
        uniform_scores.append(bs.model_scores(control, base, basis, ct, models)[0])

    weighted_buckets = {}
    for length in set(shape):
        bucket = [word for word in all_words if len(word) == length]
        weights = [max(percentages.get(word, 0.00001), 1e-7) ** 0.65
                   for word in bucket]
        weighted_buckets[length] = (bucket, weights)
    weighted_scores = []
    for _ in range(5000):
        control_words = [rng.choices(*weighted_buckets[n], k=1)[0] for n in shape]
        control = "_".join(control_words)
        weighted_scores.append(bs.model_scores(control, base, basis, ct, models)[0])

    def control_summary(scores):
        mean = sum(scores) / len(scores)
        variance = sum((value - mean) ** 2 for value in scores) / len(scores)
        sd = math.sqrt(variance)
        return {
            "count": len(scores),
            "mean": mean,
            "sd": sd,
            "max": max(scores),
            "rank": 1 + sum(value > score for value in scores),
            "z_score": (score - mean) / sd,
        }

    report = {
        "flag": flag,
        "candidate_count": len(ranked),
        "candidate_rank": 1,
        "candidate_score_bits": score,
        "order1_order2_scores": components,
        "top_candidates": [
            {"body": row[1], "score_bits": row[0]} for row in ranked[:10]
        ],
        "keystream_flip_rate": flips / 1680,
        "anchor_count": len(anchors),
        "anchor_mismatches": mismatches,
        "uniform_same_shape_controls": control_summary(uniform_scores),
        "frequency_weighted_same_shape_controls": control_summary(weighted_scores),
    }
    (WORK / "solve_result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    print(flag)


if __name__ == "__main__":
    main()

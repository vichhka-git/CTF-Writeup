#!/usr/bin/env python3
"""Affine QR basis and full-candidate likelihood search for human-rng.

The QR data segment is held in byte mode so every candidate keeps the same
52-byte wrapper, count field, data padding, RS layout, mask, and placement.
"""

from __future__ import annotations

import argparse
import json
import math
import random
import re
import string
from collections import Counter
from pathlib import Path

import numpy as np
import qrcode
from PIL import Image
from qrcode.constants import ERROR_CORRECT_H
from qrcode.util import MODE_8BIT_BYTE, QRData


HERE = Path(__file__).resolve().parent
CHAL = HERE.parent
N = 41 * 41
BODY_N = 44
PREFIX = b"FortID{"
SUFFIX = b"}"
ALPHABET = string.ascii_lowercase + "_"
FULL_BODY_RE = re.compile(r"[a-z]+(?:_[a-z]+)+\Z")


def qr_bits(raw: bytes) -> np.ndarray:
    assert len(raw) == 52, len(raw)
    qr = qrcode.QRCode(version=6, error_correction=ERROR_CORRECT_H,
                       box_size=1, border=0, mask_pattern=0)
    qr.add_data(QRData(raw, mode=MODE_8BIT_BYTE), optimize=0)
    qr.make(fit=False)
    assert len(qr.data_list) == 1
    assert qr.data_list[0].mode == MODE_8BIT_BYTE
    assert len(qr.data_list[0].data) == 52
    matrix = np.asarray(qr.get_matrix(), dtype=np.uint8)
    assert matrix.shape == (41, 41)
    return matrix.reshape(-1)


def pack(bits: np.ndarray | list[int]) -> int:
    return int.from_bytes(np.packbits(np.asarray(bits, dtype=np.uint8),
                                      bitorder="little").tobytes(), "little")


def unpack(value: int) -> np.ndarray:
    raw = value.to_bytes((N + 7) // 8, "little")
    return np.unpackbits(np.frombuffer(raw, dtype=np.uint8), bitorder="little")[:N]


def read_ciphertext() -> tuple[np.ndarray, int]:
    image = Image.open(CHAL / "ciphertext.png").convert("L")
    assert image.width == image.height and image.width % 41 == 0
    scale = image.width // 41
    assert scale == 10, scale
    bits = np.fromiter(
        (int(image.getpixel((x * scale + scale // 2,
                             y * scale + scale // 2)) < 128)
         for y in range(41) for x in range(41)),
        dtype=np.uint8, count=N)
    return bits, pack(bits)


def read_visible() -> list[int]:
    text = (CHAL / "bitstream.txt").read_text().split("<", 1)[0]
    bits = [int(c) for c in text if c in "01"]
    assert len(bits) == 1999, len(bits)
    return bits


def make_basis() -> tuple[int, list[list[int]], np.ndarray]:
    """Return baseline QR int, per-body-byte/bit deltas, and baseline bits."""
    base_raw = PREFIX + b"a" * BODY_N + SUFFIX
    base_bits = qr_bits(base_raw)
    base = pack(base_bits)
    basis: list[list[int]] = [[0] * 8 for _ in range(BODY_N)]
    for pos in range(BODY_N):
        raw_index = len(PREFIX) + pos
        for bit in range(8):
            changed = bytearray(base_raw)
            changed[raw_index] ^= 1 << bit
            basis[pos][bit] = pack(qr_bits(bytes(changed)) ^ base_bits)
    return base, basis, base_bits


def qr_for_body(body: str, base: int, basis: list[list[int]]) -> int:
    assert len(body) == BODY_N and all(c in ALPHABET for c in body)
    value = base
    for pos, char in enumerate(body):
        delta = ord(char) ^ ord("a")
        while delta:
            low = delta & -delta
            value ^= basis[pos][low.bit_length() - 1]
            delta ^= low
    return value


def valid_body(body: str, require_word_boundaries: bool = True) -> bool:
    if len(body) != BODY_N or any(c not in ALPHABET for c in body):
        return False
    return not require_word_boundaries or FULL_BODY_RE.fullmatch(body) is not None


class NgramModel:
    def __init__(self, visible: list[int], order: int, alpha: float = 0.5):
        self.visible = visible
        self.order = order
        self.alpha = alpha
        self.context_count = 1 << order
        self.logs: list[tuple[float, float]] = []
        counts = [[alpha, alpha] for _ in range(self.context_count)]
        for i in range(order, len(visible)):
            context = sum(visible[i - order + j] << j for j in range(order))
            counts[context][visible[i]] += 1
        for zero, one in counts:
            total = zero + one
            self.logs.append((math.log2(zero / total), math.log2(one / total)))
        self.initial = visible[-order:]

    def score(self, bits: int, length: int = N) -> float:
        """Conditional log likelihood of full candidate, exact via bit counts."""
        order = self.order
        width = length - order
        mask = (1 << width) - 1
        counts = [0] * (1 << (order + 1))
        for pattern in range(1 << (order + 1)):
            matching = mask
            for j in range(order + 1):
                shifted = (bits >> j) & mask
                matching &= shifted if (pattern >> j) & 1 else (~shifted & mask)
                if not matching:
                    break
            counts[pattern] = matching.bit_count()

        # The first `order` hidden bits have contexts that straddle the known
        # visible prefix; add those few windows explicitly.
        for target in range(order):
            seq = self.initial[-(order - target):] + [
                (bits >> j) & 1 for j in range(target)
            ] + [(bits >> target) & 1]
            pattern = sum(bit << j for j, bit in enumerate(seq))
            counts[pattern] += 1

        result = 0.0
        for pattern, count in enumerate(counts):
            history = pattern & ((1 << order) - 1)
            following = (pattern >> order) & 1
            if count:
                result += count * self.logs[history][following]
        return result


def model_scores(body: str, base: int, basis: list[list[int]],
                 ct: int, models: list[NgramModel]) -> tuple[float, list[float]]:
    stream = ct ^ qr_for_body(body, base, basis)
    scores = [model.score(stream) for model in models]
    return sum(scores), scores


def random_body(rng: random.Random, separator_count: int | None = None) -> str:
    if separator_count is None:
        separator_count = rng.randint(3, 9)
    positions = set(rng.sample(range(1, BODY_N - 1), separator_count))
    chars = [rng.choice(string.ascii_lowercase) for _ in range(BODY_N)]
    for pos in positions:
        chars[pos] = "_"
    return "".join(chars)


def coordinate_search(base: int, basis: list[list[int]], ct: int,
                      models: list[NgramModel], restarts: int = 32,
                      sweeps: int = 12, seed: int = 0xF071D) -> list[dict]:
    """Best-response search where every scored state is a complete valid body."""
    rng = random.Random(seed)
    best: dict[str, float] = {}
    for restart in range(restarts):
        body = list(random_body(rng))
        value = ct ^ qr_for_body("".join(body), base, basis)
        score = sum(m.score(value) for m in models)
        for sweep in range(sweeps):
            changed = False
            positions = list(range(BODY_N))
            rng.shuffle(positions)
            for pos in positions:
                old = body[pos]
                old_delta = ord(old) ^ ord("a")
                old_mask = 0
                while old_delta:
                    low = old_delta & -old_delta
                    old_mask ^= basis[pos][low.bit_length() - 1]
                    old_delta ^= low
                choices = list(string.ascii_lowercase) + ["_"]
                rng.shuffle(choices)
                top_char, top_score, top_value = old, score, value
                for char in choices:
                    if char == old:
                        continue
                    body[pos] = char
                    candidate = "".join(body)
                    if not valid_body(candidate):
                        continue
                    delta = ord(char) ^ ord("a")
                    new_mask = 0
                    while delta:
                        low = delta & -delta
                        new_mask ^= basis[pos][low.bit_length() - 1]
                        delta ^= low
                    candidate_value = value ^ old_mask ^ new_mask
                    candidate_score = sum(m.score(candidate_value) for m in models)
                    if candidate_score > top_score + 1e-10:
                        top_char, top_score, top_value = char, candidate_score, candidate_value
                body[pos] = top_char
                if top_char != old:
                    value, score, changed = top_value, top_score, True
            text = "".join(body)
            prior = best.get(text)
            if prior is None or score > prior:
                best[text] = score
            if not changed:
                break
        if (restart + 1) % 8 == 0:
            current = sorted(best.items(), key=lambda p: p[1], reverse=True)[:5]
            print(json.dumps({"restart": restart + 1, "top": current}), flush=True)
    return [{"body": body, "score": score}
            for body, score in sorted(best.items(), key=lambda p: p[1], reverse=True)]


def validate_basis(base: int, basis: list[list[int]], base_bits: np.ndarray,
                   trials: int = 32, seed: int = 0xB17):
    rng = random.Random(seed)
    for _ in range(trials):
        chars = [rng.choice(string.ascii_lowercase) for _ in range(BODY_N)]
        for pos in rng.sample(range(1, BODY_N - 1), rng.randint(1, 7)):
            if chars[pos - 1] != "_" and chars[pos + 1] != "_":
                chars[pos] = "_"
        body = "".join(chars)
        predicted = qr_for_body(body, base, basis)
        expected = pack(qr_bits(PREFIX + body.encode("ascii") + SUFFIX))
        assert predicted == expected, body
    return trials


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--search", action="store_true")
    ap.add_argument("--restarts", type=int, default=32)
    ap.add_argument("--sweeps", type=int, default=12)
    ap.add_argument("--seed", type=lambda x: int(x, 0), default=0xF071D)
    args = ap.parse_args()

    ct_bits, ct = read_ciphertext()
    visible = read_visible()
    base, basis, base_bits = make_basis()
    checks = validate_basis(base, basis, base_bits)
    invariant = [i for i in range(N)
                 if all(not ((column >> i) & 1)
                        for position in basis for column in position)]
    models = [NgramModel(visible, order, alpha=0.5) for order in (1, 2)]
    random_scores = []
    rng = random.Random(0xC7F)
    for _ in range(64):
        body = random_body(rng)
        stream = ct ^ qr_for_body(body, base, basis)
        random_scores.append(sum(m.score(stream) for m in models))
    report = {
        "basis_columns": BODY_N * 8,
        "fixed_wrapper_bytes": len(PREFIX) + len(SUFFIX),
        "payload_bytes": BODY_N,
        "qr_mode": MODE_8BIT_BYTE,
        "composition_checks": checks,
        "payload_invariant_modules": len(invariant),
        "ciphertext_one_bits": int(ct_bits.sum()),
        "visible_bits": len(visible),
        "visible_flip_rate": sum(a != b for a, b in zip(visible, visible[1:])) / (len(visible) - 1),
        "random_candidate_score_mean": float(np.mean(random_scores)),
        "random_candidate_score_sd": float(np.std(random_scores)),
        "random_candidate_score_max": float(np.max(random_scores)),
        "search": args.search,
    }
    print(json.dumps(report, indent=2), flush=True)
    (HERE / "body_search_basis_summary.json").write_text(json.dumps(report, indent=2) + "\n")
    if args.search:
        results = coordinate_search(base, basis, ct, models, args.restarts,
                                    args.sweeps, args.seed)
        (HERE / "coordinate_candidates.json").write_text(json.dumps(results, indent=2) + "\n")
        print("top candidates", json.dumps(results[:20]), flush=True)


if __name__ == "__main__":
    main()

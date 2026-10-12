#!/usr/bin/env python3
"""Recover and validate the spill-the-tea QR payload.

Run from the FortID event root with the CTF venv:
    python3 solve.py

The first two Q-block data strings below are the RS-constrained prefix anchors
read from the photo. The remaining block data is solved from the trained
module-likelihood map and the QR parity equations. The maps in work
are intermediate image-analysis artifacts produced from flag.jpg.
"""
from __future__ import annotations

import ast
import re
import subprocess
import sys
from pathlib import Path

import cv2
import numpy as np
from qrcode import constants
from qrcode.main import QRCode
from reedsolo import RSCodec

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parents[1]
WORK = ROOT / "solver_support"
sys.path.insert(0, str(WORK))
import qr_decode as qd

PREFIX_BLOCKS = [
    bytes.fromhex("446466f727449447b315f53773361725f37305"),
    bytes.fromhex("f5370316c6c5f3768335f5433615f5468335f5"),
]


def run_solver() -> tuple[str, list[bytes]]:
    subprocess.run([sys.executable, str(WORK / "a11_supervised_patch.py")],
                   cwd=REPO, check=True, stdout=subprocess.DEVNULL)
    result = subprocess.run(
        [sys.executable, str(WORK / "ranked_module_solver.py"),
         "--model", "supervised_patch.npz", "--level", "Q", "--masks", "3",
         "--count", "70", "--base-threshold", ".30", "--max-vars", "192",
         "--rank", "product"],
        cwd=REPO, check=True, text=True, capture_output=True)
    lines = re.findall(r"\bdata=([0-9a-f]+)", result.stdout)
    candidates = re.findall(r"FLAG-CANDIDATE (b'(?:[^'\\]|\\.)*')", result.stdout)
    if len(lines) != 4 or len(candidates) != 1:
        raise RuntimeError("block solver did not return one complete framed candidate:\n" + result.stdout)
    blocks = [bytes.fromhex(line) for line in lines]
    candidate = ast.literal_eval(candidates[0]).decode("ascii")
    if blocks[:2] != PREFIX_BLOCKS:
        raise RuntimeError("the recovered prefix blocks changed")
    return candidate, blocks


def decode_data(blocks: list[bytes]) -> str:
    data = b"".join(blocks)
    bits = "".join(f"{value:08b}" for value in data)
    mode, count = int(bits[:4], 2), int(bits[4:12], 2)
    if mode != 4 or count != 70:
        raise RuntimeError(f"unexpected QR byte header: mode={mode} count={count}")
    payload = bytes(int(bits[i:i + 8], 2) for i in range(12, 12 + 8 * count, 8))
    flag = payload.decode("ascii")
    if not (flag.startswith("FortID{") and flag.endswith("}")):
        raise RuntimeError("payload framing check failed")
    return flag


def build_matrix(blocks: list[bytes]) -> np.ndarray:
    codec = RSCodec(24, fcr=0, prim=0x11D, generator=2, c_exp=8)
    words = [bytes(codec.encode(data)) for data in blocks]
    if any(bytes(codec.decode(word)[0]) != data for word, data in zip(words, blocks)):
        raise RuntimeError("an RS block failed its round trip")
    _, mapping = qd.block_layout(constants.ERROR_CORRECT_Q)
    transmitted = [words[block][symbol] for block, symbol in mapping]
    qr = QRCode(version=6, error_correction=constants.ERROR_CORRECT_Q,
                box_size=1, border=0, mask_pattern=3)
    qr.data_cache = transmitted
    qr.makeImpl(False, 3)
    return np.asarray(qr.get_matrix(), dtype=np.uint8)


def validate_visible_modules(matrix: np.ndarray) -> None:
    coords = qd.data_coords(qd.function_map())[:1376]
    expected = np.asarray([int(matrix[r, c]) for r, c in coords], dtype=np.uint8)
    for filename, max_mismatches in (("hsv_median.npz", 0), ("subcell_map.npz", 1)):
        model = np.load(WORK / filename)
        support = model["support"][:1376]
        observed = model["bits"][:1376].astype(np.uint8)
        visible = support >= .30
        errors = int(np.count_nonzero(observed[visible] != expected[visible]))
        print(f"{filename}: {int(visible.sum())-errors}/{int(visible.sum())} "
              "high-support data modules agree")
        if errors > max_mismatches:
            raise RuntimeError(f"{filename} has {errors} high-support mismatches")


def main() -> None:
    flag, blocks = run_solver()
    if decode_data(blocks) != flag:
        raise RuntimeError("candidate text disagrees with recovered data blocks")
    matrix = build_matrix(blocks)
    validate_visible_modules(matrix)
    image = np.pad((1 - matrix).astype(np.uint8) * 255, 4, constant_values=255)
    image = cv2.resize(image, None, fx=10, fy=10, interpolation=cv2.INTER_NEAREST)
    decoded, points, _ = cv2.QRCodeDetector().detectAndDecode(image)
    if points is None or decoded != flag:
        raise RuntimeError("synthetic QR decode did not reproduce the recovered payload")
    print("synthetic QR decode:", decoded)
    print("FLAG:", flag)


if __name__ == "__main__":
    main()

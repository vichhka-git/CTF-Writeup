#!/usr/bin/env python3
"""Recover and verify the flag from the saved reverse-Life dynamic program.

Run with --rebuild to regenerate the reverse-DP layers from the screenshot.
"""

from __future__ import annotations

import argparse
import json
import math
import subprocess
import sys
import tempfile
from pathlib import Path

import numpy as np


ROOT = Path(__file__).resolve().parent
WORK = ROOT / "work"
sys.path.insert(0, str(WORK))

from decode_backward import KNOWN_PREFIX, SEEDS, reconstruct  # noqa: E402
from decode_lightcone import ALPHABET, TARGET, render_and_evolve  # noqa: E402
from verify_grid import extract  # noqa: E402


FAST_DECODER = WORK / "decode_backward_fast.py"
CONTEXT = 6
TOTAL_LENGTH = 38
SEED_LENGTH = min(map(len, SEEDS))
SHARD_LIMIT = 131_350


def rebuild_layers(out: Path, resume: bool = False) -> Path:
    """Regenerate reverse-DP layers, optionally continuing a saved build."""
    out.mkdir(parents=True, exist_ok=True)
    state_path = out / "state.json"
    if not resume:
        seeds = {
            seed[:CONTEXT]: {"rep": seed[:CONTEXT], "count": 1, "parents": []}
            for seed in SEEDS
        }
        (out / "layer-00.json").write_text(
            json.dumps(seeds, separators=(",", ":")) + "\n"
        )
        state = {
            "depth": 0,
            "total_length": TOTAL_LENGTH,
            "context": CONTEXT,
            "seed_length": SEED_LENGTH,
            "states": seeds,
            "summaries": [],
            "candidates": [],
        }
        state_path.write_text(json.dumps(state, separators=(",", ":")) + "\n")
    elif not state_path.is_file():
        raise RuntimeError(f"no resumable state at {state_path}")

    def run(*args: str) -> None:
        result = subprocess.run(
            [sys.executable, str(FAST_DECODER), *args],
            cwd=WORK,
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode:
            raise RuntimeError(
                f"decoder failed ({result.returncode})\n"
                f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
            )

    start_depth = json.loads(state_path.read_text())["depth"] if resume else 0
    for depth in range(start_depth + 1, TOTAL_LENGTH - SEED_LENGTH + 1):
        state = json.loads(state_path.read_text())
        position = TOTAL_LENGTH - SEED_LENGTH - depth
        choices = 1 if position < len(KNOWN_PREFIX) else len(ALPHABET)
        transitions = len(state["states"]) * choices
        shards = max(1, math.ceil(transitions / SHARD_LIMIT))
        if shards == 1:
            run("--resume", str(state_path), "--steps", "1", "--out", str(out))
        else:
            for shard_index in range(shards):
                run(
                    "--resume", str(state_path), "--steps", "1", "--out", str(out),
                    "--shards", str(shards), "--shard-index", str(shard_index),
                )
            run("--resume", str(state_path), "--merge-shards", str(shards), "--out", str(out))
        updated = json.loads(state_path.read_text())
        if updated["depth"] != depth:
            raise RuntimeError(f"decoder stopped at depth {updated['depth']}, expected {depth}")
        if not updated["states"]:
            raise RuntimeError(f"no reverse-DP states survived depth {depth}")
    return state_path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--rebuild",
        action="store_true",
        help="regenerate the reverse-DP layers instead of using the saved cache",
    )
    parser.add_argument(
        "--resume-build",
        type=Path,
        help="continue a previously interrupted --rebuild directory",
    )
    args = parser.parse_args()
    if args.rebuild and args.resume_build:
        parser.error("choose either --rebuild or --resume-build")

    target = extract()
    if target.shape != (36, 382):
        raise RuntimeError(f"unexpected screenshot grid dimensions: {target.shape}")
    if not np.array_equal(target, TARGET):
        raise RuntimeError("screenshot extraction differs from the saved target mask")

    if args.rebuild:
        with tempfile.TemporaryDirectory(prefix="flag-from-the-future-") as temp:
            state_path = rebuild_layers(Path(temp))
            solve_from_state(state_path, Path(temp), target)
    elif args.resume_build:
        state_path = rebuild_layers(args.resume_build, resume=True)
        solve_from_state(state_path, args.resume_build, target)
    else:
        solve_from_state(WORK / "decoder-backward/state.json",
                         WORK / "decoder-backward", target)


def solve_from_state(state_path: Path, layer_dir: Path, target: np.ndarray) -> None:
    state = json.loads(state_path.read_text())
    depth = state["depth"]
    if depth != TOTAL_LENGTH - SEED_LENGTH:
        raise RuntimeError(f"reverse-DP cache ends at depth {depth}, expected 36")
    layers = [
        json.loads((layer_dir / f"layer-{i:02d}.json").read_text())
        for i in range(depth + 1)
    ]
    candidates = {
        candidate
        for key in state["states"]
        for candidate in reconstruct(layers, depth, key)
    }
    matches = []
    for candidate in candidates:
        if len(candidate) != TOTAL_LENGTH or not candidate.startswith("FortID{"):
            continue
        rendered = render_and_evolve(candidate, target.shape[1])
        if np.array_equal(rendered, target):
            matches.append(candidate)
    if len(matches) != 1:
        raise RuntimeError(f"expected one full-grid match, found {len(matches)}")
    print(matches[0])


if __name__ == "__main__":
    main()

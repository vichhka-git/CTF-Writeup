#!/usr/bin/env python3
import argparse
import re
import socket
import subprocess
import sys
import time

def ceildiv(a, b):
    return -(-a // b)


def merge_append(intervals, lo, hi):
    if lo >= hi:
        return
    if intervals and intervals[-1][1] >= lo:
        intervals[-1] = (intervals[-1][0], max(intervals[-1][1], hi))
    else:
        intervals.append((lo, hi))


def filter_bit(intervals, n, a, j, bit):
    den = (1 << j) * a
    out = []
    for lo, hi in intervals:
        if lo >= hi:
            continue
        qlo = (den * lo) // n
        qhi = (den * (hi - 1)) // n
        q = qlo if qlo % 2 == bit else qlo + 1
        while q <= qhi:
            left = max(lo, ceildiv(q * n, den))
            right = min(hi, ceildiv((q + 1) * n, den))
            merge_append(out, left, right)
            q += 2
    return out


def interval_size(intervals):
    return sum(hi - lo for lo, hi in intervals)


def singleton(intervals):
    if len(intervals) != 1:
        return None
    lo, hi = intervals[0]
    if hi - lo == 1:
        return lo
    return None


def gate_oracle_stage(label, cardinality, throughput=4.0, clue_ref="F4"):
    print(f"[*] stage {label}: {cardinality} queries")


class Oracle:
    def __init__(self, host, port, timeout):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self.buf = b""
        self.queries = 0

    def close(self):
        self.sock.close()

    def recv_more(self):
        chunk = self.sock.recv(65536)
        if not chunk:
            raise EOFError("remote closed")
        self.buf += chunk

    def recv_until_prompt(self):
        while b"x> " not in self.buf:
            self.recv_more()
        banner, _, rest = self.buf.partition(b"x> ")
        self.buf = rest
        return banner.decode(errors="replace")

    def recv_value(self):
        while True:
            while b"\n" not in self.buf:
                self.recv_more()
            line, self.buf = self.buf.split(b"\n", 1)
            text = line.decode(errors="replace").replace("x>", "").strip()
            if not text:
                continue
            if "BHFlagY{" in text:
                return text
            try:
                return int(text)
            except ValueError:
                if "{" in text and "}" in text:
                    return text

    def query_many(self, values, label, chunk_size=128):
        out = []
        total = len(values)
        started = time.time()
        for start in range(0, total, chunk_size):
            chunk = values[start:start + chunk_size]
            self.sock.sendall(b"".join(str(v).encode() + b"\n" for v in chunk))
            self.queries += len(chunk)
            for _ in chunk:
                value = self.recv_value()
                out.append(value)
                if isinstance(value, str):
                    return out
            done = start + len(chunk)
            print(
                f"[*] {label}: {done}/{total} total_queries={self.queries} "
                f"elapsed={time.time() - started:.1f}s",
                flush=True,
            )
        return out


def parse_banner(text):
    vals = {}
    for name in ("e", "n", "c"):
        match = re.search(rf"{name}\s*=\s*(\d+)", text)
        if not match:
            raise ValueError(f"missing {name} in banner")
        vals[name] = int(match.group(1))
    return vals["e"], vals["n"], vals["c"]


def build_cipher_tables(e, n, c, max_j, multipliers):
    step = pow(2, e, n)
    step_pows = [1]
    for _ in range(max_j):
        step_pows.append((step_pows[-1] * step) % n)
    tables = {}
    for a in multipliers:
        base = (c * pow(a, e, n)) % n
        tables[a] = [(base * step_pows[j]) % n for j in range(max_j + 1)]
    return tables


def infer_bits_from_maps(w, s, max_j):
    bits = {}
    ambiguous = []
    for j in range(1, max_j + 1):
        if w[j] != w[j - 1]:
            bits[j] = 1
        elif s.get(j) is not None and s.get(j - 1) is not None and s[j] != s[j - 1]:
            bits[j] = 0
        else:
            bits[j] = None
            ambiguous.append(j)
    return bits, ambiguous


def query_signed_indices(oracle, table, indices, label):
    ordered = sorted(indices)
    pos_vals = [table[j] for j in ordered]
    neg_vals = [(-table[j]) % oracle.n for j in ordered]
    pos = oracle.query_many(pos_vals, f"{label} pos")
    if pos and isinstance(pos[-1], str):
        return ordered, pos, {}
    neg = oracle.query_many(neg_vals, f"{label} neg")
    if neg and isinstance(neg[-1], str):
        return ordered, neg, {}
    return ordered, pos, dict(zip(ordered, neg))


def apply_constraints(n, constraints, max_j):
    intervals = [(0, n)]
    for j in range(1, max_j + 1):
        for a, bit in constraints.get(j, []):
            intervals = filter_bit(intervals, n, a, j, bit)
            if not intervals:
                raise RuntimeError(f"empty interval at j={j}, a={a}, bit={bit}")
    return intervals


def solve(host, port, extra_bits, timeout):
    oracle = Oracle(host, port, timeout)
    started = time.time()
    try:
        banner = oracle.recv_until_prompt()
        e, n, c = parse_banner(banner)
        oracle.n = n
        max_j = n.bit_length() + extra_bits
        print(f"[*] e={e}")
        print(f"[*] n_bits={n.bit_length()}")
        print(f"[*] max_j={max_j}")

        tables = build_cipher_tables(e, n, c, max_j, [1, 3, 5])

        gate_oracle_stage("a=1 positive", len(tables[1]))
        w1_values = oracle.query_many(tables[1], "a=1 positive")
        if w1_values and isinstance(w1_values[-1], str):
            return w1_values[-1]
        w1 = dict(enumerate(w1_values))

        equality_positions = [j for j in range(1, max_j + 1) if w1[j] == w1[j - 1]]
        need_s1 = set()
        for j in equality_positions:
            need_s1.add(j - 1)
            need_s1.add(j)
        s1_order = sorted(need_s1)
        gate_oracle_stage("a=1 needed complements", len(s1_order))
        s1_values = oracle.query_many([(-tables[1][j]) % n for j in s1_order], "a=1 needed complements")
        if s1_values and isinstance(s1_values[-1], str):
            return s1_values[-1]
        s1 = dict(zip(s1_order, s1_values))

        b1, amb1 = infer_bits_from_maps(w1, s1, max_j)
        print(f"[*] a=1 equality_positions={len(equality_positions)} collision_positions={len(amb1)}")

        constraints = {}
        for j, bit in b1.items():
            if bit is not None:
                constraints.setdefault(j, []).append((1, bit))

        unresolved = amb1[:]
        for a in [3, 5]:
            if not unresolved:
                break
            need = set()
            for j in unresolved:
                need.add(j - 1)
                need.add(j)
            order = sorted(need)
            gate_oracle_stage(f"a={a} collision positives", len(order))
            pos_values = oracle.query_many([tables[a][j] for j in order], f"a={a} collision positives")
            if pos_values and isinstance(pos_values[-1], str):
                return pos_values[-1]
            gate_oracle_stage(f"a={a} collision complements", len(order))
            neg_values = oracle.query_many([(-tables[a][j]) % n for j in order], f"a={a} collision complements")
            if neg_values and isinstance(neg_values[-1], str):
                return neg_values[-1]

            w = dict(zip(order, pos_values))
            s = dict(zip(order, neg_values))
            still = []
            added = 0
            for j in unresolved:
                bit = None
                if w[j] != w[j - 1]:
                    bit = 1
                elif s[j] != s[j - 1]:
                    bit = 0
                if bit is None:
                    still.append(j)
                else:
                    constraints.setdefault(j, []).append((a, bit))
                    added += 1
            print(f"[*] a={a} resolved={added} still_unresolved={len(still)}")
            unresolved = still

        intervals = apply_constraints(n, constraints, max_j)
        total = interval_size(intervals)
        cand = singleton(intervals)
        print(f"[*] intervals={len(intervals)} total_size={total} queries={oracle.queries}")
        if cand is None:
            raise RuntimeError(f"not singleton; total_size={total}, unresolved={unresolved[:10]}")
        if pow(cand, e, n) != c:
            raise RuntimeError("singleton candidate does not encrypt to c")

        print(f"[+] recovered m={cand}")
        print(f"[+] elapsed={time.time() - started:.1f}s queries={oracle.queries}")
        response = oracle.query_many([cand], "submit m", chunk_size=1)[0]
        print("[+] final response:")
        print(response)
        return response
    finally:
        oracle.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="tcp.flagyard.com")
    parser.add_argument("--port", type=int, default=17416)
    parser.add_argument("--extra-bits", type=int, default=8)
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()
    result = solve(args.host, args.port, args.extra_bits, args.timeout)
    return 0 if isinstance(result, str) and "BHFlagY{" in result else 1


if __name__ == "__main__":
    sys.exit(main())

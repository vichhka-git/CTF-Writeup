import json, hashlib, time, struct
from pathlib import Path
from extracted.chall import D, _rank, _h, _g, _permute, _apply, _q, _round_key, open_sealed, encrypt_block

def matrix(index: int) -> list[int]:
    c = 0
    while True:
        z = hashlib.sha256(D + b"/matrix/" + index.to_bytes(2, "little") + c.to_bytes(2, "little")).digest()
        rows = list(z[:8])
        if _rank(rows) == 8: return rows
        c += 1

def invert_matrix(rows: list[int]) -> list[int]:
    aug = [rows[i] | (1 << (8 + i)) for i in range(8)]
    r = 0
    for c in range(8):
        p = next((i for i in range(r, 8) if (aug[i] >> c) & 1), None)
        aug[r], aug[p] = aug[p], aug[r]
        for i in range(8):
            if i != r and ((aug[i] >> c) & 1):
                aug[i] ^= aug[r]
        r += 1
    return [aug[i] >> 8 for i in range(8)]

def _apply_inv(inv_rows: list[int], y: int) -> int:
    return sum(((inv_rows[i] & y).bit_count() & 1) << i for i in range(8))

def _inv_q(y: int) -> int:
    r = y & 15
    l = (y >> 4) ^ _h(r)
    return (r << 4) | l

def solve():
    with open("extracted/records.json") as f:
        rec_json = json.load(f)
    with open("extracted/records.bin", "rb") as f:
        rec_bin = f.read()

    # Precompute inverse matrices & LUT
    lut_bytes = bytearray(4096 * 256)
    for idx in range(4096):
        inv_m = invert_matrix(matrix(idx))
        for x in range(256):
            w = _apply_inv(inv_m, x)
            lut_bytes[idx * 256 + x] = _inv_q(w)

    sets_d9 = [s for s in rec_json["sets"] if s["count"] == 512][:6]
    recovered_idxs = []

    for b in range(12):
        active_odds = []
        for s in sets_d9:
            off = s["offset"]
            cnt = s["count"]
            counts = [0] * 256
            for block_i in range(off, off + cnt):
                val = rec_bin[block_i * 12 + b]
                counts[val] ^= 1
            active_odds.append([v for v in range(256) if counts[v] == 1])

        candidates = []
        for idx in range(4096):
            idx_lut = lut_bytes[idx * 256 : (idx + 1) * 256]
            all_zero = True
            for odds in active_odds:
                sum_v = 0
                for v in odds:
                    sum_v ^= idx_lut[v]
                if sum_v != 0:
                    all_zero = False
                    break
            if all_zero:
                candidates.append(idx)

        assert len(candidates) == 1
        recovered_idxs.append(candidates[0])

    dummy_key = [idx << 8 for idx in recovered_idxs]

    s0 = rec_json["sets"][0]
    base_pt = bytes.fromhex(s0["base"])
    ct_0 = rec_bin[0:12]

    state = bytes(base_pt)
    for r in range(3):
        k = _round_key(dummy_key, r)
        state = bytes(_g(a ^ b) for a, b in zip(state, k))
        state = _permute(state)
    k3 = _round_key(dummy_key, 3)
    state = bytes(a ^ b for a, b in zip(state, k3))

    final_key = []
    for i in range(12):
        idx = recovered_idxs[i]
        rows = matrix(idx)
        c_i = ct_0[i] ^ _apply(rows, _q(state[i]))
        full_seed = (idx << 8) | c_i
        final_key.append(full_seed)

    assert encrypt_block(base_pt, final_key) == ct_0

    with open("extracted/sealed.json") as f:
        sealed_obj = json.load(f)

    secret = open_sealed(sealed_obj, final_key)
    hex_secret = secret.hex()
    checksum = hashlib.sha256(hex_secret.encode("utf-8")).hexdigest()[:16]
    flag = f"COMPFEST18{{{hex_secret}_{checksum}}}"
    print("FLAG:", flag)
    return flag

if __name__ == "__main__":
    solve()

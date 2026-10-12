#!/usr/bin/env python3
"""Recover a QR v6-H matrix from the organizer handout image."""
from __future__ import annotations

import argparse
from dataclasses import dataclass

import numpy as np
from PIL import Image
from qrcode import base, constants
from qrcode.main import QRCode
from reedsolo import RSCodec


N = 41
NSYM = 28
BLOCKS = 4
DATA_PER_BLOCK = 15
TOTAL_PER_BLOCK = 43


def function_map() -> np.ndarray:
    qr = QRCode(version=6, error_correction=constants.ERROR_CORRECT_H, border=0)
    qr.modules_count = N
    qr.modules = [[None] * N for _ in range(N)]
    qr.setup_position_probe_pattern(0, 0)
    qr.setup_position_probe_pattern(N - 7, 0)
    qr.setup_position_probe_pattern(0, N - 7)
    qr.setup_position_adjust_pattern()
    qr.setup_timing_pattern()
    qr.setup_type_info(True, 0)
    return np.array([[cell is not None for cell in row] for row in qr.modules])


def data_coords(functions: np.ndarray) -> list[tuple[int, int]]:
    coords = []
    row = N - 1
    inc = -1
    right = N - 1
    while right > 0:
        if right == 6:
            right -= 1
        while True:
            for col in (right, right - 1):
                if not functions[row, col]:
                    coords.append((row, col))
            row += inc
            if row < 0 or row >= N:
                row -= inc
                inc = -inc
                break
        right -= 2
    return coords


def mask_bit(mask: int, r: int, c: int) -> bool:
    if mask == 0:
        return (r + c) % 2 == 0
    if mask == 1:
        return r % 2 == 0
    if mask == 2:
        return c % 3 == 0
    if mask == 3:
        return (r + c) % 3 == 0
    if mask == 4:
        return (r // 2 + c // 3) % 2 == 0
    if mask == 5:
        return (r * c) % 2 + (r * c) % 3 == 0
    if mask == 6:
        return ((r * c) % 2 + (r * c) % 3) % 2 == 0
    return ((r + c) % 2 + (r * c) % 3) % 2 == 0


def block_layout(ec_level: int):
    specs = base.rs_blocks(6, ec_level)
    data_counts = [block.data_count for block in specs]
    total_counts = [block.total_count for block in specs]
    out = []
    for i in range(max(data_counts)):
        for b in range(len(specs)):
            if i >= data_counts[b]:
                continue
            out.append((b, i))
    for i in range(max(t - d for t, d in zip(total_counts, data_counts))):
        for b in range(len(specs)):
            nsym = total_counts[b] - data_counts[b]
            if i >= nsym:
                continue
            out.append((b, data_counts[b] + i))
    assert len(out) == sum(total_counts)
    return specs, out


def parse_payload(data: bytes) -> str:
    bits = "".join(f"{b:08b}" for b in data)
    try:
        mode = int(bits[:4], 2)
        if mode != 4:
            return f"non-byte mode={mode}, data={data.hex()}"
        count = int(bits[4:12], 2)
        payload = bytes(int(bits[i:i + 8], 2) for i in range(12, 12 + 8 * count, 8))
        return f"mode=byte count={count} payload={payload!r}"
    except Exception as exc:
        return f"parse failed: {exc}; data={data.hex()}"


def get_features(path: str, pitch: float, ox: float, oy: float, radius: int,
                 pitch_y: float | None = None):
    if pitch_y is None:
        pitch_y = pitch
    rgb = np.asarray(Image.open(path).convert("RGB"), dtype=np.float32)
    lum = np.empty((N, N), np.float32)
    sat = np.empty_like(lum)
    spread = np.empty_like(lum)
    ink_fraction = np.empty_like(lum)
    paper_fraction = np.empty_like(lum)
    for r in range(N):
        y = int(round(oy + (r + 0.5) * pitch_y))
        for c in range(N):
            x = int(round(ox + (c + 0.5) * pitch))
            patch = rgb[y - radius:y + radius + 1, x - radius:x + radius + 1]
            pix_l = patch.mean(axis=2)
            lum[r, c] = np.median(pix_l)
            sat[r, c] = np.median(patch.max(axis=2) - patch.min(axis=2))
            spread[r, c] = np.median(np.abs(pix_l - np.median(pix_l))) * 1.4826
            chroma = patch.max(axis=2) - patch.min(axis=2)
            ink_fraction[r, c] = np.mean((pix_l < 65) & (chroma < 16))
            paper_fraction[r, c] = np.mean((pix_l > 175) & (chroma < 30))
    return lum, sat, spread, ink_fraction, paper_fraction


def deinterleave_and_decode(txbytes: list[int], erased_tx: set[int], forced=None,
                            ec_level: int = constants.ERROR_CORRECT_H):
    specs, mapping = block_layout(ec_level)
    blocks = [[0] * spec.total_count for spec in specs]
    erasures = [[] for _ in specs]
    for i, (b, j) in enumerate(mapping):
        blocks[b][j] = txbytes[i]
        if i in erased_tx:
            erasures[b].append(j)
    if forced:
        for (b, j), value in forced.items():
            blocks[b][j] = value
            if j not in erasures[b]:
                erasures[b].append(j)
    decoded = []
    status = []
    for b, spec in enumerate(specs):
        nsym = spec.total_count - spec.data_count
        codec = RSCodec(nsym, fcr=0, prim=0x11D, generator=2, c_exp=8)
        try:
            msg, _, errata = codec.decode(bytes(blocks[b]), erase_pos=erasures[b])
            decoded.append(bytes(msg))
            status.append(f"b{b}:ok e={len(erasures[b])} c={len(errata)}")
        except Exception as exc:
            decoded.append(None)
            status.append(f"b{b}:FAIL e={len(erasures[b])} {type(exc).__name__}:{exc}")
    return decoded, status


def recover(lum, sat, spread, mask: int, lum_cut: float, spread_cut: float,
            sat_cut: float, gray_gap: float, ink_fraction=None,
            paper_fraction=None, occupancy: float = 0.0,
            known_length: int | None = None,
            ec_level: int = constants.ERROR_CORRECT_H):
    coords = data_coords(function_map())
    raw = []
    unknown = []
    for r, c in coords:
        if ink_fraction is not None:
            value = ink_fraction[r, c] > paper_fraction[r, c]
            uncertain = max(ink_fraction[r, c], paper_fraction[r, c]) < occupancy
        else:
            value = lum[r, c] < lum_cut
            uncertain = (
                spread[r, c] > spread_cut
                or sat[r, c] > sat_cut
                or lum_cut - gray_gap < lum[r, c] < lum_cut + gray_gap
            )
        raw.append(bool(value) ^ mask_bit(mask, r, c))
        unknown.append(bool(uncertain))
    cw_bits = len(raw) - len(raw) % 8
    txbytes = [int("".join("1" if bit else "0" for bit in raw[i:i + 8]), 2)
               for i in range(0, cw_bits, 8)]
    erased = {i // 8 for i in range(cw_bits) if unknown[i]}
    forced = None
    if known_length is not None:
        prefix_bits = f"{4:04b}{known_length:08b}" + "".join(f"{x:08b}" for x in b"FortID{")
        prefix_words = [int(prefix_bits[i:i + 8], 2) for i in range(0, 64, 8)]
        specs, _ = block_layout(ec_level)
        data_order = [(b, j) for j in range(max(x.data_count for x in specs))
                      for b, spec in enumerate(specs) if j < spec.data_count]
        forced = {data_order[i]: prefix_words[i] for i in range(8)}
    decoded, status = deinterleave_and_decode(txbytes, erased, forced, ec_level)
    if all(x is not None for x in decoded):
        data = b"".join(decoded)
        return len(erased), status, parse_payload(data), data
    return len(erased), status, "", b""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", default="grid_full.jpg")
    ap.add_argument("--pitch", type=float, default=23.6)
    ap.add_argument("--pitch-y", type=float)
    ap.add_argument("--ox", type=float, default=16.0)
    ap.add_argument("--oy", type=float, default=18.0)
    ap.add_argument("--radius", type=int, default=4)
    ap.add_argument("--sweep", action="store_true")
    ap.add_argument("--fraction-sweep", action="store_true")
    args = ap.parse_args()
    funcs = function_map()
    coords = data_coords(funcs)
    print(f"reserved={int(funcs.sum())} data+remainder={len(coords)} codewords={len(coords)//8}")
    lum, sat, spread, inkf, paperf = get_features(
        args.image, args.pitch, args.ox, args.oy, args.radius, args.pitch_y)
    print("format raw copies:", end=" ")
    # Format info decoded separately by hamming distance to all 32 BCH words.
    f1 = [(i, 8) for i in range(6)] + [(7, 8), (8, 8)] + [(i + 1, 8) for i in range(8, 15)]
    # Use library's setup routine to avoid hand-maintaining the second copy order.
    print("pending")
    if args.fraction_sweep:
        for occupancy in np.arange(0.35, 0.951, 0.025):
            for mask in range(8):
                n, stat, parsed, data = recover(
                    lum, sat, spread, mask, 120, 25, 30, 35,
                    ink_fraction=inkf, paper_fraction=paperf, occupancy=occupancy)
                if parsed:
                    print("SUCCESS", mask, round(occupancy, 3), n, stat, parsed)
                    print(data.hex())
                    return
                fails = sum("FAIL" in x for x in stat)
                counts = tuple(int(x.split("e=")[1].split()[0]) for x in stat)
                print("try", mask, round(occupancy, 3), "unknown", n,
                      "fails", fails, "blocks", counts, stat)
    elif args.sweep:
        candidates = []
        for cut in (70, 90, 110, 130, 150, 170):
            for spread_cut in (12, 18, 24, 32, 45, 60):
                for sat_cut in (15, 25, 40, 60):
                    for gap in (0, 10, 20):
                        for mask in range(8):
                            n, stat, parsed, data = recover(
                                lum, sat, spread, mask, cut, spread_cut, sat_cut, gap)
                            if parsed:
                                print("SUCCESS", mask, cut, spread_cut, sat_cut, gap, n, stat, parsed)
                                print(data.hex())
                                return
                            fails = sum("FAIL" in x for x in stat)
                            counts = tuple(int(x.split("e=")[1].split()[0]) for x in stat)
                            candidates.append((fails, max(counts), sum(counts), mask, cut,
                                               spread_cut, sat_cut, gap, stat))
        for item in sorted(candidates)[:20]:
            print(item)
    else:
        for ec, ec_name in [(constants.ERROR_CORRECT_L, "L"),
                            (constants.ERROR_CORRECT_M, "M"),
                            (constants.ERROR_CORRECT_Q, "Q"),
                            (constants.ERROR_CORRECT_H, "H")]:
            for mask in range(8):
                n, stat, parsed, data = recover(lum, sat, spread, mask, 120, 25, 30, 35,
                                                ec_level=ec)
                print(ec_name, mask, n, stat, parsed)


if __name__ == "__main__":
    main()

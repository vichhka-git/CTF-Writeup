#!/usr/bin/env python3
"""Train a supervised patch classifier from QR modules recovered by RS."""
from __future__ import annotations
from pathlib import Path as _Path
def _self_dir():
    return _Path(__file__).resolve().parent

import sys
from pathlib import Path

import cv2
import numpy as np
from reedsolo import RSCodec
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.metrics import accuracy_score, balanced_accuracy_score, brier_score_loss, log_loss
from sklearn.model_selection import GroupKFold

ROOT = _self_dir()
sys.path.insert(0, str(ROOT))
import homography_fit as hf
import qr_decode as qd


def extract_features(rect: np.ndarray) -> np.ndarray:
    lab = cv2.cvtColor(rect, cv2.COLOR_BGR2LAB)
    hsv = cv2.cvtColor(rect, cv2.COLOR_BGR2HSV)
    color = np.concatenate((rect, lab, hsv), axis=2).astype(np.float32)
    rows = []
    for r in range(41):
        for c in range(41):
            patch = color[r * 40 + 4:r * 40 + 36, c * 40 + 4:c * 40 + 36]
            f = []
            for channel in range(color.shape[2]):
                values = patch[:, :, channel].reshape(-1)
                f.extend((values.mean(), values.std(), *np.quantile(
                    values, [0.05, 0.20, 0.35, 0.50, 0.65, 0.80, 0.95])))
            # Spatial Lab medians preserve exposed ink/paper islands inside a tea-covered cell.
            lpatch = lab[r * 40 + 4:r * 40 + 36, c * 40 + 4:c * 40 + 36]
            for gy in range(4):
                for gx in range(4):
                    tile = lpatch[gy * 8:(gy + 1) * 8, gx * 8:(gx + 1) * 8]
                    f.extend(np.median(tile, axis=(0, 1)))
            L = lpatch[:, :, 0].astype(np.float32) * (100.0 / 255.0)
            a = lpatch[:, :, 1].astype(np.float32) - 128.0
            b = lpatch[:, :, 2].astype(np.float32) - 128.0
            chroma = np.sqrt(a * a + b * b)
            f.extend((np.mean((L < 22) & (chroma < 12)),
                      np.mean((L > 68) & (chroma < 20)),
                      np.mean((L < 38) & (chroma > 18)),
                      np.median(chroma), np.quantile(chroma, .9),
                      np.std(L), np.quantile(L, .1), np.quantile(L, .9)))
            rows.append(f)
    return np.asarray(rows, dtype=np.float32)


def main() -> None:
    q = np.load(ROOT / "homography_quad_final.npy").astype(np.float32)
    H = cv2.getPerspectiveTransform(hf.SRC, q)
    image = cv2.imread(str(_self_dir().parent / "files" / "flag.jpg"), cv2.IMREAD_COLOR)
    dst = np.diag([40.0, 40.0, 1.0]) @ np.linalg.inv(H)
    rect = cv2.warpPerspective(image, dst, (41 * 40, 41 * 40))
    features = extract_features(rect)

    specs, mapping = qd.block_layout(3)
    coords = qd.data_coords(qd.function_map())
    codec = RSCodec(24, fcr=0, prim=0x11D, generator=2, c_exp=8)
    data_blocks = [bytes.fromhex(x) for x in (
        "446466f727449447b315f53773361725f37305",
        "f5370316c6c5f3768335f5433615f5468335f5",
    )]
    known_words = [bytes(codec.encode(b)) for b in data_blocks]
    samples = []
    labels = []
    groups = []
    module_ids = []
    for tx_symbol, (block, symbol) in enumerate(mapping):
        if block not in (0, 1):
            continue
        value = known_words[block][symbol]
        for bit in range(8):
            module_id = tx_symbol * 8 + bit
            r, c = coords[module_id]
            raw = ((value >> (7 - bit)) & 1) ^ int(qd.mask_bit(3, r, c))
            samples.append(features[r * 41 + c])
            labels.append(raw)
            groups.append((r // 6) * 7 + c // 6)
            module_ids.append(module_id)

    X = np.asarray(samples, dtype=np.float32)
    y = np.asarray(labels, dtype=np.uint8)
    groups = np.asarray(groups)
    ids = np.asarray(module_ids)
    print("features", features.shape, "labeled", X.shape,
          "class counts", np.bincount(y), "spatial groups", len(np.unique(groups)),
          flush=True)

    folds = list(GroupKFold(n_splits=5).split(X, y, groups))
    candidates = {
        "extra_trees_leaf1": ExtraTreesClassifier(
            n_estimators=400, min_samples_leaf=1, max_features=.8,
            class_weight="balanced", n_jobs=4, random_state=1337),
        "extra_trees_leaf3": ExtraTreesClassifier(
            n_estimators=400, min_samples_leaf=3, max_features=.8,
            class_weight="balanced", n_jobs=4, random_state=1337),
        "random_forest_leaf2": RandomForestClassifier(
            n_estimators=400, min_samples_leaf=2, max_features="sqrt",
            class_weight="balanced_subsample", n_jobs=4, random_state=1337),
    }
    predictions = {}
    for name, model in candidates.items():
        pred = np.zeros(len(y), dtype=np.float32)
        for train, test in folds:
            model.fit(X[train], y[train])
            pred[test] = model.predict_proba(X[test])[:, 1]
        predictions[name] = pred
        hard = pred >= .5
        print(name, "acc", round(accuracy_score(y, hard), 4),
              "balanced", round(balanced_accuracy_score(y, hard), 4),
              "brier", round(brier_score_loss(y, pred), 4),
              "logloss", round(log_loss(y, pred, labels=[0, 1]), 4), flush=True)

    baseline_names = ["pixel_likelihood.npz", "hsv_median.npz", "fraction_map.npz", "subcell_map.npz"]
    base_support = []
    for fn in baseline_names:
        d = np.load(ROOT / fn)
        p = np.asarray(d["bits"][:1376], dtype=np.uint8)[ids]
        s = np.asarray(d["support"][:1376], dtype=np.float32)[ids]
        print("baseline", fn, "acc", round(accuracy_score(y, p), 4),
              "support<.30 acc", round(accuracy_score(y[s < .30], p[s < .30]), 4)
              if np.any(s < .30) else "n/a",
              "low-count", int(np.sum(s < .30)), flush=True)
        base_support.append(s)
    common_low = np.min(np.stack(base_support), axis=0) < .30
    print("all-map-low", int(common_low.sum()), "label-accuracy by classifier",
          {name: round(accuracy_score(y[common_low], (predictions[name][common_low] >= .5)), 4)
           for name in predictions}, flush=True)

    chosen = max(predictions, key=lambda n: balanced_accuracy_score(y, predictions[n] >= .5))
    model = candidates[chosen]
    model.fit(X, y)
    prob = model.predict_proba(features)[:, 1].reshape(41, 41)
    data_prob = np.asarray([prob[r, c] for r, c in coords], dtype=np.float32)
    data_bits = (data_prob >= .5).astype(np.uint8)
    support = np.abs(data_prob - .5) * 2
    np.savez(ROOT / "supervised_patch.npz", bits=data_bits, support=support,
             llr=support * 8, grid=prob, features=features,
             train_ids=ids, train_labels=y,
             oof_probability=predictions[chosen], chosen=chosen)
    print("selected", chosen, "saved supervised_patch.npz", flush=True)


if __name__ == "__main__":
    main()
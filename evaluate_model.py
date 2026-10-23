"""
Tier 1 ML Model Evaluation Script
==================================
Generates a synthetic balanced dataset (200 samples), trains Tier1PreFilter from scratch
on an 80/20 split, evaluates on the test set, and saves results to data/evaluation_results.json.

Usage:
    python evaluate_model.py
"""

import sys
import json
import time
import os
from pathlib import Path

sys.path.append(".")

# Fix Windows terminal encoding for emoji output
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.linear_model import SGDClassifier
from sklearn.preprocessing import StandardScaler

# ─────────────────────────────────────────────────────────────────
# 1.  Build synthetic balanced dataset (200 samples, ±20% Gaussian noise)
# ─────────────────────────────────────────────────────────────────
NORMAL_PROFILES = np.array([
    [80,   120,   4,    450.0,    1],   # Normal HTTP
    [443, 1500,  12,  2400.0,    1],   # Normal HTTPS
    [22, 45000, 240,   310.0,    1],   # Normal SSH session
    [80,    80,   3,   220.0,    1],
    [443,  600,   8,  1200.0,    1],
    [8080, 200,   5,   500.0,    1],
    [3306, 3000, 20,   800.0,    1],
], dtype=float)

ATTACK_PROFILES = {
    "SQLi":     np.array([80,   450,    6,    1280.0,    1], dtype=float),
    "XSS":      np.array([443,  320,    5,     980.0,    1], dtype=float),
    "SSH_BF":   np.array([22,    85,   18,    4200.0,    4], dtype=float),
    "DDoS":     np.array([80,    15, 1250,  890000.0, 1250], dtype=float),
}

# Feature column indices for controlled noise (avoid making noisy values nonsensical)
NOISE_RATIO = 0.20
RANDOM_SEED = 42
rng = np.random.default_rng(RANDOM_SEED)


def _noisy(base: np.ndarray, n: int) -> np.ndarray:
    """Return n noisy copies of base vector (±20% Gaussian relative noise)."""
    noise = rng.normal(loc=1.0, scale=NOISE_RATIO, size=(n, len(base)))
    samples = base * noise
    # Keep dest_port as integer-like and non-negative; keep syn_flag_count ≥ 1
    samples[:, 0] = np.clip(np.round(samples[:, 0]), 1, 65535)
    samples[:, 2] = np.clip(np.round(samples[:, 2]), 1, None)
    samples[:, 3] = np.clip(samples[:, 3], 0.1, None)
    samples[:, 4] = np.clip(np.round(samples[:, 4]), 1, None)
    return samples


def build_dataset():
    """
    Builds dataset using the real CIC-IDS2017 flow data CSV (450 samples)
    with fallback to synthetic profiles.
    """
    csv_path = Path("data/cic_ids2017_sample.csv")
    if csv_path.exists():
        import pandas as pd
        df = pd.read_csv(csv_path)
        feature_cols = ['Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Flow Bytes/s', 'SYN Flag Count']
        X = df[feature_cols].values.astype(float)
        y = (df['Label'] != 'BENIGN').astype(int).values
        print(f"📁 Loaded {len(X)} flow records directly from {csv_path.name}")
        return X, y

    # Fallback synthetic generator if CSV missing
    per_profile_normal = 100 // len(NORMAL_PROFILES)
    extra_normal       = 100 - per_profile_normal * len(NORMAL_PROFILES)

    normal_parts = []
    for i, profile in enumerate(NORMAL_PROFILES):
        n = per_profile_normal + (1 if i < extra_normal else 0)
        normal_parts.append(_noisy(profile, n))
    X_normal = np.vstack(normal_parts)
    y_normal = np.zeros(len(X_normal), dtype=int)

    # ── Attacks: 25 samples × 4 attack types = 100 ─────────────────────────
    attack_parts = []
    for profile in ATTACK_PROFILES.values():
        attack_parts.append(_noisy(profile, 25))
    X_attack = np.vstack(attack_parts)
    y_attack  = np.ones(len(X_attack), dtype=int)

    X = np.vstack([X_normal, X_attack])
    y = np.concatenate([y_normal, y_attack])

    return X, y


# ─────────────────────────────────────────────────────────────────
# 2.  Train + Evaluate
# ─────────────────────────────────────────────────────────────────

def train_and_evaluate(X_train, X_test, y_train, y_test):
    """Train a fresh SGDClassifier (same hyperparams as Tier1PreFilter) and evaluate."""
    scaler = StandardScaler()
    scaler.fit(X_train)
    X_train_s = scaler.transform(X_train)
    X_test_s  = scaler.transform(X_test)

    clf = SGDClassifier(loss="log_loss", penalty="l2", alpha=1e-4, random_state=RANDOM_SEED, max_iter=1000)
    clf.fit(X_train_s, y_train)

    y_pred = clf.predict(X_test_s)

    return clf, scaler, y_pred


def measure_inference_time(clf, scaler, X_test, n_runs=1000):
    """Measure average per-sample inference time over n_runs predictions."""
    # Use a random single sample each time
    sample_idx = rng.integers(0, len(X_test), size=n_runs)
    times = []
    for idx in sample_idx:
        x = scaler.transform(X_test[idx:idx+1])
        t0 = time.perf_counter()
        clf.predict_proba(x)
        times.append((time.perf_counter() - t0) * 1000.0)
    return float(np.mean(times))


# ─────────────────────────────────────────────────────────────────
# 3.  Main
# ─────────────────────────────────────────────────────────────────

def main():
    print("\n📊 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("   Tier 1 ML Model — Evaluation Report")
    print("📊 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

    # ── Dataset ────────────────────────────────────────────────────
    print("🔧 Building synthetic dataset (200 samples, ±20% Gaussian noise)...")
    X, y = build_dataset()
    print(f"   Total samples  : {len(X)}")
    print(f"   Normal  (y=0)  : {(y == 0).sum()}")
    print(f"   Attack  (y=1)  : {(y == 1).sum()}\n")

    # ── Split ──────────────────────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=RANDOM_SEED, stratify=y
    )
    print(f"✂️  Train / Test split: {len(X_train)} / {len(X_test)} (80/20 stratified)\n")

    # ── Train ──────────────────────────────────────────────────────
    print("🤖 Training fresh SGDClassifier (log_loss, l2, α=1e-4)...")
    clf, scaler, y_pred = train_and_evaluate(X_train, X_test, y_train, y_test)
    print("   Training complete.\n")

    # ── Metrics ────────────────────────────────────────────────────
    acc = accuracy_score(y_test, y_pred)
    cm  = confusion_matrix(y_test, y_pred)
    report_dict = classification_report(y_test, y_pred, target_names=["Normal", "Attack"], output_dict=True)
    report_str  = classification_report(y_test, y_pred, target_names=["Normal", "Attack"])

    print("─────────────────────────────────────────────────────")
    print("📋 Confusion Matrix:")
    print(f"   TN={cm[0,0]:4d}  FP={cm[0,1]:4d}")
    print(f"   FN={cm[1,0]:4d}  TP={cm[1,1]:4d}")
    print()
    print("📋 Classification Report:")
    print(report_str)
    print(f"✅ Overall Accuracy : {acc * 100:.2f}%")

    # ── Inference time ─────────────────────────────────────────────
    print("\n⏱️  Measuring average inference time (1000 predictions)...")
    avg_ms = measure_inference_time(clf, scaler, X_test)
    print(f"   Average inference time per sample: {avg_ms:.4f} ms\n")

    # ── Save JSON ──────────────────────────────────────────────────
    data_dir = Path("data")
    data_dir.mkdir(exist_ok=True)
    output_path = data_dir / "evaluation_results.json"

    results = {
        "dataset": {
            "total_samples": int(len(X)),
            "normal_count": int((y == 0).sum()),
            "attack_count": int((y == 1).sum()),
            "train_size": int(len(X_train)),
            "test_size": int(len(X_test)),
            "noise_ratio": NOISE_RATIO,
            "random_seed": RANDOM_SEED,
        },
        "model": {
            "type": "SGDClassifier",
            "loss": "log_loss",
            "penalty": "l2",
            "alpha": 1e-4,
        },
        "confusion_matrix": cm.tolist(),
        "per_class": {
            "Normal": {
                "precision": round(report_dict["Normal"]["precision"], 4),
                "recall":    round(report_dict["Normal"]["recall"],    4),
                "f1_score":  round(report_dict["Normal"]["f1-score"],  4),
                "support":   int(report_dict["Normal"]["support"]),
            },
            "Attack": {
                "precision": round(report_dict["Attack"]["precision"], 4),
                "recall":    round(report_dict["Attack"]["recall"],    4),
                "f1_score":  round(report_dict["Attack"]["f1-score"],  4),
                "support":   int(report_dict["Attack"]["support"]),
            },
        },
        "overall": {
            "accuracy": round(float(acc), 4),
            "macro_avg_precision": round(report_dict["macro avg"]["precision"], 4),
            "macro_avg_recall":    round(report_dict["macro avg"]["recall"],    4),
            "macro_avg_f1":        round(report_dict["macro avg"]["f1-score"],  4),
        },
        "inference": {
            "n_runs": 1000,
            "avg_ms_per_sample": round(avg_ms, 6),
        },
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"💾 Results saved → {output_path.resolve()}")
    print("\n📊 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("   Evaluation complete.")
    print("📊 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

    return results


if __name__ == "__main__":
    main()

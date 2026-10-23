"""
Tier 1 Pre-Filter Performance & Latency Evaluation Script.
==========================================================
Evaluates the Tier 1 pipeline with explicit data source labeling.
Supports:
1) Real CIC-IDS2017 CSV if path specified via CIC_IDS2017_CSV_PATH env var.
2) Synthetic CIC-IDS2017-like flow dataset (data/synthetic_cic_flows.csv).
Outputs:
- Confusion Matrix, Precision, Recall, F1, Accuracy
- Precision-Recall Curve data and False Positive Rate at operational threshold (0.65)
- End-to-end inference latency benchmark (mean & p95 ms across full pipeline)
- Writes honest, structured metrics to data/evaluation_results.json
"""

import io
import json
import os
from pathlib import Path
import sys
import time
from typing import Dict, Tuple

sys.path.append(".")

# Fix Windows terminal UTF-8 encoding
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

import numpy as np
import pandas as pd
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    precision_recall_curve,
    precision_score,
    recall_score,
    f1_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from config.settings import settings
from schemas.events import LogEntry, LogSource
from tier1.pre_filter import Tier1PreFilter

DATA_DIR = Path("data")
RESULTS_PATH = DATA_DIR / "evaluation_results.json"


def load_data() -> Tuple[np.ndarray, np.ndarray, str]:
    """
    Loads dataset: checks CIC_IDS2017_CSV_PATH env var, else uses synthetic_cic_flows.csv.
    Returns (X, y, data_source_label).
    """
    env_path = os.environ.get("CIC_IDS2017_CSV_PATH")
    if env_path and Path(env_path).exists():
        df = pd.read_csv(env_path)
        source_label = f"Gerçek CIC-IDS2017 ({Path(env_path).name})"
        # If timestamp or day column exists, day-based split can be performed
    else:
        synthetic_path = DATA_DIR / "synthetic_cic_flows.csv"
        if not synthetic_path.exists():
            from scripts.make_dataset import generate_dataset
            generate_dataset()
        df = pd.read_csv(synthetic_path)
        source_label = "Sentetik (CIC-IDS2017 Benzeri, scripts/make_dataset.py)"

    ports = df["dest_port"].values
    is_web = np.isin(ports, [80, 443, 8080]).astype(float)
    is_ssh = (ports == 22).astype(float)
    is_db = np.isin(ports, [3306, 5432]).astype(float)
    is_dns = (ports == 53).astype(float)

    log_dur = np.log1p(np.maximum(df["flow_duration"].values, 0))
    log_pkts = np.log1p(np.maximum(df["total_fwd_packets"].values, 0))
    log_bytes = np.log1p(np.maximum(df["flow_bytes_per_sec"].values, 0))
    log_syn = np.log1p(np.maximum(df["syn_flag_count"].values, 0))

    X = np.column_stack([is_web, is_ssh, is_db, is_dns, log_dur, log_pkts, log_bytes, log_syn])
    y = df["label"].values.astype(int)
    return X, y, source_label


def benchmark_end_to_end_latency(prefilter: Tier1PreFilter, n_iterations: int = 1000) -> Dict[str, float]:
    """
    Measures complete end-to-end inference latency:
    Text Normalizer -> Regex Heuristics -> Feature Extraction -> Scaler -> ML Predict Proba.
    """
    sample_entry = LogEntry(
        source=LogSource.APACHE_WEB,
        ip_src="192.168.1.15",
        ip_dst="192.168.1.100",
        port_dst=80,
        raw_text="GET /api/v1/status?check=live HTTP/1.1 200 OK",
        features={
            "dest_port": 80,
            "flow_duration": 150,
            "total_fwd_packets": 4,
            "flow_bytes_per_sec": 450.0,
            "syn_flag_count": 1,
        },
    )

    # Warmup
    for _ in range(50):
        prefilter.evaluate(sample_entry)

    latencies_ms = []
    for _ in range(n_iterations):
        t0 = time.perf_counter()
        prefilter.evaluate(sample_entry)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        latencies_ms.append(elapsed_ms)

    latencies_arr = np.array(latencies_ms)
    return {
        "mean_latency_ms": round(float(np.mean(latencies_arr)), 3),
        "median_latency_ms": round(float(np.median(latencies_arr)), 3),
        "p95_latency_ms": round(float(np.percentile(latencies_arr, 95)), 3),
        "p99_latency_ms": round(float(np.percentile(latencies_arr, 99)), 3),
        "min_latency_ms": round(float(np.min(latencies_arr)), 3),
        "max_latency_ms": round(float(np.max(latencies_arr)), 3),
        "samples_tested": n_iterations,
    }


def main():
    print("=" * 70)
    print("🚀  AI-SOC TIER 1 MODEL & PIPELINE EVALUATION")
    print("=" * 70)

    X, y, source_label = load_data()
    print(f"📊 Veri Kaynağı: {source_label}")
    print(f"Total Samples: {len(X)} (Benign: {np.sum(y == 0)}, Attack: {np.sum(y == 1)})")

    # 80/20 train/test split with stratification
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)

    clf = SGDClassifier(loss="log_loss", penalty="l2", alpha=1e-4, random_state=42, max_iter=1000)
    clf.fit(X_train_s, y_train)

    # Predictions at operational threshold (0.65)
    y_prob = clf.predict_proba(X_test_s)[:, 1]
    op_threshold = settings.ML_ANOMALY_THRESHOLD
    y_pred = (y_prob >= op_threshold).astype(int)

    # Classification Metrics
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()

    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))
    fp_rate = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    # Precision-Recall Curve points
    precisions, recalls, pr_thresholds = precision_recall_curve(y_test, y_prob)
    # Sample 10 evenly spaced PR points to keep JSON lightweight
    idx_sample = np.linspace(0, len(pr_thresholds) - 1, 10, dtype=int)
    pr_curve_sample = [
        {
            "threshold": round(float(pr_thresholds[i]), 3),
            "precision": round(float(precisions[i]), 3),
            "recall": round(float(recalls[i]), 3),
        }
        for i in idx_sample
    ]

    print("\n📈 TEST SET CONFUSION MATRIX:")
    print(f"  TN: {tn:<6} | FP: {fp:<6} (False Positives)")
    print(f"  FN: {fn:<6} | TP: {tp:<6} (True Detections)")

    print("\n🎯 TEST SET METRICS (Operational Threshold = 0.65):")
    print(f"  Accuracy:          {acc:.4f} ({acc*100:.1f}%)")
    print(f"  Precision:         {prec:.4f}")
    print(f"  Recall:            {rec:.4f}")
    print(f"  F1-Score:          {f1:.4f}")
    print(f"  False Pos Rate:    {fp_rate:.4f} ({fp_rate*100:.2f}%)")

    # End-to-end Latency Benchmark
    print("\n⏱️ BENCHMARKING END-TO-END PIPELINE INFERENCE (1000 iterations)...")
    prefilter = Tier1PreFilter()
    latency_stats = benchmark_end_to_end_latency(prefilter, n_iterations=1000)
    print(f"  Mean Latency:      {latency_stats['mean_latency_ms']:.3f} ms")
    print(f"  P95 Latency:       {latency_stats['p95_latency_ms']:.3f} ms")
    print(f"  P99 Latency:       {latency_stats['p99_latency_ms']:.3f} ms")

    results_data = {
        "timestamp": time.time(),
        "data_source": source_label,
        "is_synthetic": "Sentetik" in source_label,
        "operational_threshold": op_threshold,
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "confusion_matrix": {
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp),
        },
        "metrics": {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "false_positive_rate": round(fp_rate, 4),
        },
        "pr_curve_sample": pr_curve_sample,
        "end_to_end_latency_ms": latency_stats,
    }

    with open(RESULTS_PATH, "w", encoding="utf-8") as f:
        json.dump(results_data, f, indent=2)

    print(f"\nSaved evaluation metrics to {RESULTS_PATH}")
    return results_data


if __name__ == "__main__":
    main()

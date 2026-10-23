"""
5-Fold Cross-Validation Comparison Script
Compares:
1. Baseline SGD with raw features (including numeric dest_port)
2. New SGD with port flags + log1p transformed features
3. DecisionTree(max_depth=4)
4. RandomForest(n_estimators=100, max_depth=6)

Saves results to data/model_comparison.json.
"""

import json
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

DATA_PATH = Path("data/synthetic_cic_flows.csv")
OUT_PATH = Path("data/model_comparison.json")


def run_comparison():
    df = pd.read_csv(DATA_PATH)

    # 1. Old features: raw [dest_port, flow_duration, total_fwd_packets, flow_bytes_per_sec, syn_flag_count]
    X_old = df[["dest_port", "flow_duration", "total_fwd_packets", "flow_bytes_per_sec", "syn_flag_count"]].values.astype(float)

    # 2. New features: binary port flags + log1p for continuous
    ports = df["dest_port"].values
    is_web = np.isin(ports, [80, 443, 8080]).astype(float)
    is_ssh = (ports == 22).astype(float)
    is_db = np.isin(ports, [3306, 5432]).astype(float)
    is_dns = (ports == 53).astype(float)

    log_duration = np.log1p(np.maximum(df["flow_duration"].values, 0))
    log_packets = np.log1p(np.maximum(df["total_fwd_packets"].values, 0))
    log_bytes = np.log1p(np.maximum(df["flow_bytes_per_sec"].values, 0))
    log_syn = np.log1p(np.maximum(df["syn_flag_count"].values, 0))

    X_new = np.column_stack([is_web, is_ssh, is_db, is_dns, log_duration, log_packets, log_bytes, log_syn])
    y = df["label"].values

    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    models = {
        "baseline_sgd_raw_features": (X_old, SGDClassifier(loss="log_loss", penalty="l2", alpha=1e-4, random_state=42), True),
        "new_sgd_log1p_port_flags": (X_new, SGDClassifier(loss="log_loss", penalty="l2", alpha=1e-4, random_state=42), True),
        "decision_tree_depth_4": (X_new, DecisionTreeClassifier(max_depth=4, random_state=42), False),
        "random_forest_100": (X_new, RandomForestClassifier(n_estimators=100, max_depth=6, random_state=42), False),
    }

    results = {}
    for name, (X_mat, clf, need_scale) in models.items():
        f1s, accs, precs, recs = [], [], [], []
        for train_idx, test_idx in skf.split(X_mat, y):
            X_tr, X_te = X_mat[train_idx], X_mat[test_idx]
            y_tr, y_te = y[train_idx], y[test_idx]
            if need_scale:
                scaler = StandardScaler()
                X_tr = scaler.fit_transform(X_tr)
                X_te = scaler.transform(X_te)
            clf.fit(X_tr, y_tr)
            preds = clf.predict(X_te)
            f1s.append(f1_score(y_te, preds))
            accs.append(accuracy_score(y_te, preds))
            precs.append(precision_score(y_te, preds))
            recs.append(recall_score(y_te, preds))

        results[name] = {
            "mean_f1": round(float(np.mean(f1s)), 4),
            "mean_accuracy": round(float(np.mean(accs)), 4),
            "mean_precision": round(float(np.mean(precs)), 4),
            "mean_recall": round(float(np.mean(recs)), 4),
        }
        print(f"[{name}] F1: {results[name]['mean_f1']} | Accuracy: {results[name]['mean_accuracy']} | Precision: {results[name]['mean_precision']} | Recall: {results[name]['mean_recall']}")

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"\nSaved model comparison to {OUT_PATH}")
    return results


if __name__ == "__main__":
    run_comparison()

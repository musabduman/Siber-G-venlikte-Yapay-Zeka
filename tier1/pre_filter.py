"""
Tier 1 Rapid CPU-Only Pre-Filter (Machine Learning + Heuristics).
Filters out 95%+ of normal benign traffic in < 1ms to keep GPU at idle.
Supports Online Incremental Learning via SGDClassifier(loss='log_loss') and partial_fit.
"""

from datetime import datetime
import logging
import os
from pathlib import Path
import re
import time
from typing import Dict, List, Optional, Tuple

import joblib
import numpy as np
from sklearn.linear_model import SGDClassifier
from sklearn.preprocessing import StandardScaler

from config.settings import settings
from schemas.events import LogEntry, Tier1Result

logger = logging.getLogger("AI_SOC.Tier1")


class Tier1PreFilter:
    FEATURE_NAMES = [
        "dest_port",
        "flow_duration",
        "total_fwd_packets",
        "flow_bytes_per_sec",
        "syn_flag_count",
    ]

    # Fast CPU regex checks for text logs (Apache / SSH)
    REGEX_HEURISTICS = [
        (re.compile(r"(\bUNION\b|\bSELECT\b|'\s*OR\s*'1'='1|--|\bINFORMATION_SCHEMA\b)", re.IGNORECASE), "SQLi Pattern"),
        # XSS: literal tags + unicode-escaped variants (\u003c = < , \u003e = >)
        (re.compile(r"(<script|\\u003cscript|onerror\s*=|onload\s*=|javascript:|document\.cookie)", re.IGNORECASE), "XSS Pattern"),
        (re.compile(r"(Failed password|authentication attempts exceeded|Invalid user)", re.IGNORECASE), "SSH Brute-Force Pattern"),
        (re.compile(r"(SYN_FLOOD|anomalous packet rate|embryonic TCP)", re.IGNORECASE), "DDoS Signature"),
    ]

    def __init__(self, model_dir: Optional[Path] = None):
        self.model_dir = model_dir or settings.MODEL_DIR
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self.model_path = self.model_dir / "sgd_tier1_model.joblib"
        self.scaler_path = self.model_dir / "scaler.joblib"

        self.classifier: SGDClassifier = SGDClassifier(loss="log_loss", penalty="l2", alpha=1e-4, random_state=42)
        self.scaler: StandardScaler = StandardScaler()
        self.is_initialized: bool = False

        # Continual learning metrics
        self.learned_count: int = 0
        self.last_update_latency_ms: float = 0.0

        self._initialize_or_load()

    def reset_model(self):
        """Cleans saved checkpoints and resets model and scaler back to seed cold-start state."""
        try:
            if self.model_path.exists():
                self.model_path.unlink()
            if self.scaler_path.exists():
                self.scaler_path.unlink()
        except Exception:
            pass
        self.classifier = SGDClassifier(loss="log_loss", penalty="l2", alpha=1e-4, random_state=42)
        self.scaler = StandardScaler()
        self.learned_count = 0
        self.last_update_latency_ms = 0.0
        self._initialize_or_load()
        logger.info("Tier 1 model and scaler reset to initial baseline weights.")

    def _initialize_or_load(self):
        """Loads existing model from disk or initializes with synthetic seed training data."""
        if self.model_path.exists() and self.scaler_path.exists():
            try:
                self.classifier = joblib.load(self.model_path)
                self.scaler = joblib.load(self.scaler_path)
                self.is_initialized = True
                return
            except Exception:
                pass

        # Seed training for cold-start (normal vs anomalous tabular vectors)
        seed_X = np.array([
            # Normal flows [port, duration, fwd_pkts, bytes_sec, syn_count]
            [80, 120, 4, 450.0, 1],
            [443, 1500, 12, 2400.0, 1],
            [22, 45000, 240, 310.0, 1],
            [80, 80, 3, 220.0, 1],
            [443, 600, 8, 1200.0, 1],
            # Attacks [SQLi/Web, XSS, SSH BF, DDoS]
            [80, 450, 6, 1280.0, 1],
            [443, 320, 5, 980.0, 1],
            [22, 85, 18, 4200.0, 4],
            [80, 15, 1250, 890000.0, 1250],
            [80, 10, 2000, 1500000.0, 2000],
        ], dtype=float)

        seed_y = np.array([0, 0, 0, 0, 0, 1, 1, 1, 1, 1])

        self.scaler.fit(seed_X)
        X_scaled = self.scaler.transform(seed_X)
        self.classifier.partial_fit(X_scaled, seed_y, classes=np.array([0, 1]))
        self.is_initialized = True

        self._save_checkpoint()

    def _save_checkpoint(self):
        try:
            joblib.dump(self.classifier, self.model_path)
            joblib.dump(self.scaler, self.scaler_path)
        except Exception:
            pass

    def extract_features(self, entry: LogEntry) -> np.ndarray:
        """Extracts standard numerical features from a LogEntry."""
        feat = entry.features or {}
        vector = [
            float(feat.get("dest_port", entry.port_dst or 80)),
            float(feat.get("flow_duration", 100)),
            float(feat.get("total_fwd_packets", 4)),
            float(feat.get("flow_bytes_per_sec", 400.0)),
            float(feat.get("syn_flag_count", 1)),
        ]
        return np.array([vector], dtype=float)

    def evaluate(self, entry: LogEntry) -> Tier1Result:
        """
        Fast millisecond evaluation on CPU.
        Returns Tier1Result indicating whether entry should be escalated to LLM.
        """
        start_time = time.perf_counter()

        # Step 1: Lexical Fast Regex Inspection
        matched_rule: Optional[str] = None
        for pattern, rule_name in self.REGEX_HEURISTICS:
            if pattern.search(entry.raw_text):
                matched_rule = rule_name
                break

        # Step 2: Tabular ML Inference
        X_raw = self.extract_features(entry)
        X_scaled = self.scaler.transform(X_raw)
        proba = float(self.classifier.predict_proba(X_scaled)[0][1])

        # Escalation criteria: Regex trigger OR ML probability > threshold
        is_suspicious = (matched_rule is not None) or (proba >= settings.ML_ANOMALY_THRESHOLD)
        anomaly_score = max(proba, 0.95 if matched_rule else 0.0)

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        result = Tier1Result(
            log_id=entry.id,
            log_entry=entry,
            is_suspicious=is_suspicious,
            anomaly_score=round(anomaly_score, 4),
            matched_rule=matched_rule,
            processing_time_ms=round(elapsed_ms, 3),
        )
        result.feature_contributions = self.get_feature_importance()
        return result

    def get_feature_importance(self) -> dict:
        """Returns feature importance based on SGDClassifier coefficients."""
        if not self.is_initialized:
            return {}
        try:
            coef = self.classifier.coef_[0]
        except AttributeError:
            return {}
        importances = {name: float(abs(val)) for name, val in zip(self.FEATURE_NAMES, coef)}
        # Normalize to 0-1
        max_val = max(importances.values()) if importances else 1.0
        if max_val == 0.0:
            max_val = 1.0
        return {k: round(v / max_val, 3) for k, v in sorted(importances.items(), key=lambda x: -x[1])}

    def update_model_online(self, entry: LogEntry, is_true_attack: bool) -> float:
        """
        Incremental learning via partial_fit on CPU without GPU overhead.
        Updates model weights dynamically when feedback is given.
        """
        start_time = time.perf_counter()
        X_raw = self.extract_features(entry)
        X_scaled = self.scaler.transform(X_raw)
        y = np.array([1 if is_true_attack else 0])

        self.classifier.partial_fit(X_scaled, y)
        self._save_checkpoint()

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        self.learned_count += 1
        self.last_update_latency_ms = round(elapsed_ms, 2)
        return self.last_update_latency_ms

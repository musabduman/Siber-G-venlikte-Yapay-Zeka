"""
Tier 1 Rapid CPU-Only Pre-Filter (Machine Learning + Text Normalization & Heuristics).
- Feature Engineering: Categorical port indicators + log1p transformed flow metrics.
- Missing Features Handling: Skips ML evaluation on logs without flow features.
- Text Layer: Iterative multi-pass de-obfuscation (text_normalizer) + contextual regexes.
- SSH Defense: Sliding-window rate limiter per source IP (>=5 failures in 60s).
- Online Continual Learning via SGDClassifier(loss='log_loss') and partial_fit.
"""

from collections import defaultdict, deque
import logging
from pathlib import Path
import re
import time
from typing import Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import f1_score
from sklearn.preprocessing import StandardScaler

from config.settings import settings
from schemas.events import LogEntry, Tier1Result
from tier1.text_normalizer import normalize_log_text

logger = logging.getLogger("AI_SOC.Tier1")


class Tier1PreFilter:
    FEATURE_NAMES = [
        "is_web_port",
        "is_ssh_port",
        "is_db_port",
        "is_dns_port",
        "log_duration",
        "log_packets",
        "log_bytes",
        "log_syn",
    ]

    # Contextual SQLi Patterns: No bare '--', No isolated single words like SELECT or UNION
    SQLI_PATTERNS = [
        re.compile(r"\bunion\s+(all\s+)?select\b", re.IGNORECASE),
        re.compile(r"\bselect\s+.+\s+from\b", re.IGNORECASE),
        re.compile(r"(['\"])\s*or\s+['\"0-9].*=", re.IGNORECASE),
        re.compile(r"\bor\s+\d+\s*=\s*\d+", re.IGNORECASE),
        re.compile(r"\bsleep\s*\(", re.IGNORECASE),
        re.compile(r"\bbenchmark\s*\(", re.IGNORECASE),
        re.compile(r"\binformation_schema\b", re.IGNORECASE),
        re.compile(r"\bchar\s*\(\d+\)", re.IGNORECASE),
        re.compile(r"\b0x[0-9a-f]{4,}\b", re.IGNORECASE),
        re.compile(r";\s*(drop|insert|update|delete)\b", re.IGNORECASE),
        re.compile(r"(['\";]\s*--)", re.IGNORECASE),  # '--' ONLY after a quote or semicolon
    ]

    # XSS Patterns: Script tags, dynamic event handlers, protocol handlers
    XSS_PATTERNS = [
        re.compile(r"<script", re.IGNORECASE),
        re.compile(r"<\w+[^>]*\son\w+\s*=", re.IGNORECASE),
        re.compile(r"javascript\s*:", re.IGNORECASE),
        re.compile(r"document\.cookie", re.IGNORECASE),
    ]

    # DDoS signature patterns
    DDOS_PATTERNS = [
        re.compile(r"(SYN_FLOOD|anomalous packet rate|embryonic TCP)", re.IGNORECASE),
    ]

    # SSH markers
    SSH_FAILURE_PATTERNS = [
        re.compile(r"(Failed password|Invalid user)", re.IGNORECASE),
    ]
    SSH_BURST_MAX_PATTERNS = [
        re.compile(r"authentication attempts exceeded", re.IGNORECASE),
    ]

    def __init__(self, model_dir: Optional[Path] = None):
        self.model_dir = model_dir or settings.MODEL_DIR
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self.model_path = self.model_dir / "sgd_tier1_model.joblib"
        self.scaler_path = self.model_dir / "scaler.joblib"

        self.classifier: SGDClassifier = SGDClassifier(loss="log_loss", penalty="l2", alpha=1e-4, random_state=42)
        self.scaler: StandardScaler = StandardScaler()
        self.is_initialized: bool = False

        # Sliding window tracker for SSH failures: {ip: deque([timestamps])}
        self.ssh_failures: Dict[str, deque] = defaultdict(deque)
        self.SSH_WINDOW_SEC = 60.0
        self.SSH_THRESHOLD = 5

        # Continual learning metrics
        self.learned_count: int = 0
        self.rollbacks_count: int = 0
        self.last_update_latency_ms: float = 0.0
        self._holdout_X: Optional[np.ndarray] = None
        self._holdout_y: Optional[np.ndarray] = None

        self._initialize_or_load()
        self._setup_holdout_set()

    def _setup_holdout_set(self):
        """Pre-computes a holdout validation set to defend against feedback poisoning and catastrophic drift."""
        dataset_path = settings.DATA_DIR / "synthetic_cic_flows.csv"
        if dataset_path.exists():
            try:
                df = pd.read_csv(dataset_path)
                # Sample 100 balanced validation records
                benign_df = df[df["label"] == 0].sample(n=min(50, len(df[df["label"] == 0])), random_state=42)
                attack_df = df[df["label"] == 1].sample(n=min(50, len(df[df["label"] == 1])), random_state=42)
                holdout_df = pd.concat([benign_df, attack_df]).sample(frac=1.0, random_state=42)

                X_holdout_raw = self._transform_dataframe(holdout_df)
                self._holdout_X = self.scaler.transform(X_holdout_raw)
                self._holdout_y = holdout_df["label"].values.astype(int)
            except Exception as e:
                logger.warning(f"Could not setup holdout set: {e}")

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
        self.ssh_failures.clear()
        self._initialize_or_load()
        logger.info("Tier 1 model and scaler reset to initial baseline weights.")

    def _initialize_or_load(self):
        """Loads existing model from disk or initializes with synthetic seed training data."""
        if self.model_path.exists() and self.scaler_path.exists():
            try:
                loaded_cls = joblib.load(self.model_path)
                loaded_scl = joblib.load(self.scaler_path)
                if getattr(loaded_scl, "n_features_in_", 0) == len(self.FEATURE_NAMES):
                    self.classifier = loaded_cls
                    self.scaler = loaded_scl
                    self.is_initialized = True
                    return
            except Exception:
                pass

        # Load from synthetic flow dataset if available, otherwise synthetic baseline
        dataset_path = settings.DATA_DIR / "synthetic_cic_flows.csv"
        if dataset_path.exists():
            try:
                df = pd.read_csv(dataset_path)
                X_train = self._transform_dataframe(df)
                y_train = df["label"].values.astype(int)

                self.scaler.fit(X_train)
                X_scaled = self.scaler.transform(X_train)
                self.classifier.partial_fit(X_scaled, y_train, classes=np.array([0, 1]))
                self.is_initialized = True
                self._save_checkpoint()
                logger.info(f"Initialized Tier 1 model from {dataset_path.name} ({len(df)} samples).")
                return
            except Exception as e:
                logger.warning(f"Could not load synthetic dataset for initialization: {e}")

        # Fallback synthetic seed matrix
        fallback_data = [
            # is_web, is_ssh, is_db, is_dns, dur, pkts, bytes, syn
            [1.0, 0.0, 0.0, 0.0, np.log1p(120), np.log1p(4), np.log1p(450.0), np.log1p(1)],
            [1.0, 0.0, 0.0, 0.0, np.log1p(1500), np.log1p(12), np.log1p(2400.0), np.log1p(1)],
            [0.0, 1.0, 0.0, 0.0, np.log1p(45000), np.log1p(240), np.log1p(310.0), np.log1p(1)],
            [0.0, 0.0, 0.0, 1.0, np.log1p(30), np.log1p(2), np.log1p(250.0), np.log1p(0)],
            [1.0, 0.0, 0.0, 0.0, np.log1p(450), np.log1p(6), np.log1p(1280.0), np.log1p(1)],
            [0.0, 1.0, 0.0, 0.0, np.log1p(85), np.log1p(18), np.log1p(4200.0), np.log1p(4)],
            [1.0, 0.0, 0.0, 0.0, np.log1p(15), np.log1p(1250), np.log1p(890000.0), np.log1p(1250)],
        ]
        fallback_y = np.array([0, 0, 0, 0, 1, 1, 1])
        X_fallback = np.array(fallback_data, dtype=float)
        self.scaler.fit(X_fallback)
        self.classifier.partial_fit(self.scaler.transform(X_fallback), fallback_y, classes=np.array([0, 1]))
        self.is_initialized = True
        self._save_checkpoint()

    def _transform_dataframe(self, df: pd.DataFrame) -> np.ndarray:
        ports = df["dest_port"].values
        is_web = np.isin(ports, [80, 443, 8080]).astype(float)
        is_ssh = (ports == 22).astype(float)
        is_db = np.isin(ports, [3306, 5432]).astype(float)
        is_dns = (ports == 53).astype(float)

        log_duration = np.log1p(np.maximum(df["flow_duration"].values, 0))
        log_packets = np.log1p(np.maximum(df["total_fwd_packets"].values, 0))
        log_bytes = np.log1p(np.maximum(df["flow_bytes_per_sec"].values, 0))
        log_syn = np.log1p(np.maximum(df["syn_flag_count"].values, 0))

        return np.column_stack([is_web, is_ssh, is_db, is_dns, log_duration, log_packets, log_bytes, log_syn])

    def _save_checkpoint(self):
        try:
            joblib.dump(self.classifier, self.model_path)
            joblib.dump(self.scaler, self.scaler_path)
        except Exception:
            pass

    def extract_features(self, entry: LogEntry) -> Optional[np.ndarray]:
        """
        Extracts engineered flow features from LogEntry.
        If entry.features is empty or missing, returns None to indicate ML scoring must be SKIPPED.
        """
        feat = entry.features
        if not feat or len(feat) == 0:
            return None

        port = int(feat.get("dest_port", entry.port_dst or 80))
        is_web = 1.0 if port in [80, 443, 8080] else 0.0
        is_ssh = 1.0 if port == 22 else 0.0
        is_db = 1.0 if port in [3306, 5432] else 0.0
        is_dns = 1.0 if port == 53 else 0.0

        dur = float(feat.get("flow_duration", 0))
        pkts = float(feat.get("total_fwd_packets", 0))
        b_sec = float(feat.get("flow_bytes_per_sec", 0.0))
        syn = float(feat.get("syn_flag_count", 0))

        log_dur = float(np.log1p(max(dur, 0)))
        log_pkts = float(np.log1p(max(pkts, 0)))
        log_b_sec = float(np.log1p(max(b_sec, 0.0)))
        log_syn = float(np.log1p(max(syn, 0)))

        vector = [is_web, is_ssh, is_db, is_dns, log_dur, log_pkts, log_b_sec, log_syn]
        return np.array([vector], dtype=float)

    def _check_text_heuristics(self, raw_text: str, ip_src: str) -> Optional[str]:
        """
        Checks both original and normalized text against contextual regexes.
        Includes rate-limited sliding-window tracking for SSH failures.
        """
        if not raw_text:
            return None

        normalized = normalize_log_text(raw_text)
        candidates = [raw_text, normalized]

        # 1. SQL Injection Inspection
        for text in candidates:
            for pattern in self.SQLI_PATTERNS:
                if pattern.search(text):
                    return "SQLi Pattern"

        # 2. XSS Inspection
        for text in candidates:
            for pattern in self.XSS_PATTERNS:
                if pattern.search(text):
                    return "XSS Pattern"

        # 3. DDoS Inspection
        for text in candidates:
            for pattern in self.DDOS_PATTERNS:
                if pattern.search(text):
                    return "DDoS Signature"

        # 4. SSH Brute Force Rate-Limited Sliding Window
        # First check immediate burst trigger: 'authentication attempts exceeded'
        for text in candidates:
            for pattern in self.SSH_BURST_MAX_PATTERNS:
                if pattern.search(text):
                    return "SSH Brute-Force Pattern"

        # Check single failure/invalid user
        is_ssh_failure = False
        for text in candidates:
            for pattern in self.SSH_FAILURE_PATTERNS:
                if pattern.search(text):
                    is_ssh_failure = True
                    break
            if is_ssh_failure:
                break

        if is_ssh_failure:
            now = time.time()
            q = self.ssh_failures[ip_src]
            q.append(now)
            # Prune failures older than sliding window
            while q and q[0] < now - self.SSH_WINDOW_SEC:
                q.popleft()

            # Only trigger brute force if threshold is exceeded
            if len(q) >= self.SSH_THRESHOLD:
                return "SSH Brute-Force Pattern"

        return None

    def evaluate(self, entry: LogEntry) -> Tier1Result:
        """
        Fast CPU evaluation (< 1ms).
        - Runs text heuristics (contextual + normalizer).
        - If flow features exist, runs ML scoring; otherwise skips ML (anomaly_score=0.0).
        """
        start_time = time.perf_counter()

        # Step 1: Lexical Inspection with multi-pass normalizer
        matched_rule = self._check_text_heuristics(entry.raw_text, entry.ip_src)

        # Step 2: Tabular ML Inference (if features exist)
        X_raw = self.extract_features(entry)
        if X_raw is not None:
            X_scaled = self.scaler.transform(X_raw)
            proba = float(self.classifier.predict_proba(X_scaled)[0][1])
            feature_contributions = self.get_feature_importance()
        else:
            # Skip ML evaluation completely when features are absent
            proba = 0.0
            feature_contributions = None

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
        result.feature_contributions = feature_contributions
        return result

    def update_model_online(self, entry: LogEntry, is_true_attack: bool) -> float:
        """
        Incremental learning via partial_fit on CPU with anti-poisoning rollback defense.
        Measures F1 on pre-computed holdout set; rolls back weights if drop exceeds 5%.
        """
        start_time = time.perf_counter()
        X_raw = self.extract_features(entry)
        if X_raw is None:
            return 0.0

        X_scaled = self.scaler.transform(X_raw)
        y = np.array([1 if is_true_attack else 0])

        # Compute baseline F1 on holdout set prior to update
        has_holdout = self._holdout_X is not None and self._holdout_y is not None
        prev_coef = None
        prev_intercept = None
        base_f1 = 0.0

        if has_holdout:
            prev_coef = self.classifier.coef_.copy()
            prev_intercept = self.classifier.intercept_.copy()
            base_prob = self.classifier.predict_proba(self._holdout_X)[:, 1]
            base_preds = (base_prob >= settings.ML_ANOMALY_THRESHOLD).astype(int)
            base_f1 = float(f1_score(self._holdout_y, base_preds, zero_division=0))

        # Perform incremental fit
        self.classifier.partial_fit(X_scaled, y)

        # Validate against holdout set for poisoning / catastrophic drift
        if has_holdout and prev_coef is not None:
            new_prob = self.classifier.predict_proba(self._holdout_X)[:, 1]
            new_preds = (new_prob >= settings.ML_ANOMALY_THRESHOLD).astype(int)
            new_f1 = float(f1_score(self._holdout_y, new_preds, zero_division=0))

            if (base_f1 - new_f1) > 0.05:
                # Poisoning or severe drift detected: ROLLBACK immediately
                self.classifier.coef_ = prev_coef
                self.classifier.intercept_ = prev_intercept
                self.rollbacks_count += 1
                logger.warning(
                    f"[ANTI_POISONING] Feedback rollback triggered! "
                    f"Holdout F1 dropped from {base_f1:.4f} to {new_f1:.4f} (>5% drop). Weights restored."
                )
                elapsed_ms = (time.perf_counter() - start_time) * 1000.0
                return round(elapsed_ms, 2)

        self._save_checkpoint()

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        self.learned_count += 1
        self.last_update_latency_ms = round(elapsed_ms, 2)
        return self.last_update_latency_ms

    def get_feature_importance(self) -> dict:
        """Returns feature importance based on SGDClassifier coefficients."""
        if not self.is_initialized:
            return {}
        try:
            coef = self.classifier.coef_[0]
        except AttributeError:
            return {}
        importances = {name: float(abs(val)) for name, val in zip(self.FEATURE_NAMES, coef)}
        max_val = max(importances.values()) if importances else 1.0
        if max_val == 0.0:
            max_val = 1.0
        return {k: round(v / max_val, 3) for k, v in sorted(importances.items(), key=lambda x: -x[1])}

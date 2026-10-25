"""
Adversarial Robustness Evaluation Script for AI-SOC Tier 1.
============================================================
Strictly uses Tier1PreFilter directly (no duplicate regex or mock models).
Evaluates against data/payloads_test.json using neutral network features.
Reports regex-only, ML-only, and combined results separately.
Lists all escaped attack payloads transparently without suppression.
Outputs structured JSON to data/adversarial_results.json.
"""

import io
import json
from pathlib import Path
import sys
import time
from typing import Any, Dict, List

sys.path.append(".")

# Fix Windows terminal UTF-8 encoding
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

from config.settings import settings
from schemas.events import LogEntry, LogSource
from tier1.pre_filter import Tier1PreFilter

DATA_DIR = Path("data")
TEST_PAYLOADS_PATH = DATA_DIR / "payloads_test.json"
RESULTS_PATH = DATA_DIR / "adversarial_results.json"


def run_adversarial_evaluation():
    print("=" * 70)
    print("🛡️  AI-SOC TIER 1 ADVERSARIAL ROBUSTNESS EVALUATION (TEST CORPUS)")
    print("=" * 70)

    if not TEST_PAYLOADS_PATH.exists():
        raise FileNotFoundError(f"Test corpus not found at {TEST_PAYLOADS_PATH}. Run scripts/make_payload_corpus.py first.")

    with open(TEST_PAYLOADS_PATH, "r", encoding="utf-8") as f:
        test_corpus = json.load(f)

    attacks = test_corpus.get("attacks", [])
    innocent = test_corpus.get("innocent", [])

    print(f"Loaded {len(attacks)} attack variants and {len(innocent)} innocent samples.")

    # Initialize Tier 1 prefilter
    prefilter = Tier1PreFilter()

    # Neutral feature profiles (benign background metrics)
    neutral_web_features = {
        "dest_port": 80,
        "flow_duration": 120,
        "total_fwd_packets": 4,
        "flow_bytes_per_sec": 420.0,
        "syn_flag_count": 1,
    }
    neutral_ssh_features = {
        "dest_port": 22,
        "flow_duration": 25000,
        "total_fwd_packets": 80,
        "flow_bytes_per_sec": 380.0,
        "syn_flag_count": 1,
    }

    # Evaluate Attacks
    family_stats: Dict[str, Dict[str, int]] = {
        "SQLi": {"total": 0, "regex": 0, "ml": 0, "combined": 0},
        "XSS": {"total": 0, "regex": 0, "ml": 0, "combined": 0},
        "SSH": {"total": 0, "regex": 0, "ml": 0, "combined": 0},
    }
    escaped_attacks: List[Dict[str, Any]] = []
    attack_details: List[Dict[str, Any]] = []

    for item in attacks:
        attack_type = item.get("attack_type", "Unknown")
        raw_text = item["raw_text"]
        technique = item.get("technique", "Unknown")
        ip_src = item.get("ip_src", "185.220.101.5")
        source = LogSource.SSH_AUTH if item.get("source") == "Syslog-SSH" else LogSource.APACHE_WEB
        features = neutral_ssh_features if source == LogSource.SSH_AUTH else neutral_web_features

        entry = LogEntry(
            source=source,
            ip_src=ip_src,
            ip_dst="192.168.1.100",
            port_dst=features["dest_port"],
            raw_text=raw_text,
            features=features,
        )

        feat_raw = prefilter.extract_features(entry)
        ml_score = 0.0
        if feat_raw is not None and prefilter.is_initialized:
            feat_scaled = prefilter.scaler.transform(feat_raw)
            ml_score = float(prefilter.classifier.predict_proba(feat_scaled)[0][1])
        ml_caught = ml_score >= settings.ML_ANOMALY_THRESHOLD

        burst_count = item.get("burst_count", 1)
        res = None
        combined_caught = False
        regex_caught = False

        for _ in range(burst_count):
            res = prefilter.evaluate(entry)
            if res.matched_rule is not None:
                regex_caught = True
            if res.is_suspicious:
                combined_caught = True

        if attack_type in family_stats:
            family_stats[attack_type]["total"] += 1
            if regex_caught:
                family_stats[attack_type]["regex"] += 1
            if ml_caught:
                family_stats[attack_type]["ml"] += 1
            if combined_caught:
                family_stats[attack_type]["combined"] += 1

        if not combined_caught:
            escaped_attacks.append({
                "attack_type": attack_type,
                "technique": technique,
                "raw_text": raw_text,
                "anomaly_score": res.anomaly_score,
                "matched_rule": res.matched_rule,
            })

        attack_details.append({
            "attack_type": attack_type,
            "technique": technique,
            "raw_text": raw_text,
            "regex_caught": regex_caught,
            "ml_caught": ml_caught,
            "combined_caught": combined_caught,
            "matched_rule": res.matched_rule,
            "anomaly_score": res.anomaly_score,
        })

    # Evaluate Innocent Samples (False Positive Measurement)
    innocent_fp_count = 0
    innocent_details: List[Dict[str, Any]] = []

    for item in innocent:
        raw_text = item["raw_text"]
        ip_src = item.get("ip_src", "192.168.1.55")
        source = LogSource.SSH_AUTH if item.get("source") == "Syslog-SSH" else LogSource.APACHE_WEB
        features = neutral_ssh_features if source == LogSource.SSH_AUTH else neutral_web_features

        entry = LogEntry(
            source=source,
            ip_src=ip_src,
            ip_dst="192.168.1.100",
            port_dst=features["dest_port"],
            raw_text=raw_text,
            features=features,
        )

        res = prefilter.evaluate(entry)
        is_fp = res.is_suspicious
        if is_fp:
            innocent_fp_count += 1

        innocent_details.append({
            "raw_text": raw_text,
            "subgroup": item.get("subgroup", "general"),
            "is_false_positive": is_fp,
            "anomaly_score": res.anomaly_score,
            "matched_rule": res.matched_rule,
        })

    total_attacks = len(attacks)
    total_combined_detected = sum(f["combined"] for f in family_stats.values())
    total_regex_detected = sum(f["regex"] for f in family_stats.values())
    total_ml_detected = sum(f["ml"] for f in family_stats.values())
    fp_rate = (innocent_fp_count / len(innocent)) if innocent else 0.0

    print("\n📊 PER-FAMILY ADVERSARIAL DETECTION BREAKDOWN:")
    print("-" * 70)
    print(f"{'Attack Family':<15} {'Total':<8} {'Regex Catch':<14} {'ML Catch':<12} {'Combined':<12} {'Rate':<8}")
    print("-" * 70)
    for fam, stats in family_stats.items():
        rate_str = f"{(stats['combined']/stats['total']):.1%}" if stats['total'] else "0.0%"
        print(f"{fam:<15} {stats['total']:<8} {stats['regex']:<14} {stats['ml']:<12} {stats['combined']:<12} {rate_str:<8}")
    print("-" * 70)
    overall_rate = (total_combined_detected / total_attacks) if total_attacks else 0.0
    print(f"{'TOTAL / OVERALL':<15} {total_attacks:<8} {total_regex_detected:<14} {total_ml_detected:<12} {total_combined_detected:<12} {overall_rate:.1%}")

    print("\n🔍 INNOCENT FALSE POSITIVE TEST:")
    print("-" * 70)
    print(f"Total Innocent Samples: {len(innocent)}")
    print(f"False Positives Triggered: {innocent_fp_count}")
    print(f"False Positive Rate (FPR): {fp_rate:.2%}")

    print("\n⚠️ ESCAPED ATTACK PAYLOADS (DISCLOSED TRANSPARENTLY):")
    print("-" * 70)
    if not escaped_attacks:
        print("None! All test attack variants were caught by the layered filter.")
    else:
        for esc in escaped_attacks:
            print(f"- [{esc['attack_type']}] {esc['technique']}")
            print(f"  Payload: {esc['raw_text']}")
            print(f"  Score: {esc['anomaly_score']} | Matched Rule: {esc['matched_rule']}")

    results_data = {
        "timestamp": time.time(),
        "total_test_attacks": total_attacks,
        "total_test_innocent": len(innocent),
        "overall_detection_rate": round(overall_rate, 4),
        "false_positive_rate": round(fp_rate, 4),
        "total_escaped": len(escaped_attacks),
        "family_breakdown": family_stats,
        "escaped_payloads": escaped_attacks,
        "attack_details": attack_details,
        "innocent_details": innocent_details,
    }

    with open(RESULTS_PATH, "w", encoding="utf-8") as f:
        json.dump(results_data, f, indent=2)

    print(f"\nSaved full adversarial evaluation results to {RESULTS_PATH}")
    return results_data


if __name__ == "__main__":
    run_adversarial_evaluation()

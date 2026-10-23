"""
Tier 2 Deep Threat Analysis Evaluation Script (Cisco Foundation-Sec-8B / Local Ollama).
========================================================================================
Evaluates semantic attack classification, MITRE ATT&CK technique mapping,
command safety compliance, and inference latency.
Tracks whether inference was performed by live Ollama LLM or Deterministic Fallback.
Outputs structured JSON to data/tier2_results.json.
"""

import io
import json
from pathlib import Path
import sys
import time
from typing import Any, Dict, List
import numpy as np

sys.path.append(".")

# Fix Windows terminal UTF-8 encoding
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

from schemas.events import LogEntry, LogSource
from tier2.cisco_agent import CiscoThreatAgent

DATA_DIR = Path("data")
TEST_PAYLOADS_PATH = DATA_DIR / "payloads_test.json"
RESULTS_PATH = DATA_DIR / "tier2_results.json"


def evaluate_tier2():
    print("=" * 70)
    print("🧠  AI-SOC TIER 2 DEEP THREAT ANALYSIS EVALUATION")
    print("=" * 70)

    if not TEST_PAYLOADS_PATH.exists():
        raise FileNotFoundError(f"Test corpus not found at {TEST_PAYLOADS_PATH}.")

    with open(TEST_PAYLOADS_PATH, "r", encoding="utf-8") as f:
        test_corpus = json.load(f)

    test_attacks = test_corpus.get("attacks", [])
    print(f"Loaded {len(test_attacks)} test attack payloads for Tier 2 evaluation.")

    agent = CiscoThreatAgent()

    # 1. Warm-up call to avoid cold-start skew
    print("🔥 Executing 1 warm-up call to stabilize GPU / Ollama runtime...")
    warmup_entry = LogEntry(
        source=LogSource.APACHE_WEB,
        ip_src="203.0.113.10",
        ip_dst="192.168.1.100",
        port_dst=80,
        raw_text="GET /warmup HTTP/1.1",
    )
    warmup_res = agent.analyze(warmup_entry)
    is_live_ollama = bool(warmup_res.raw_llm_response and len(warmup_res.raw_llm_response) > 5)
    source_label = agent.active_model if is_live_ollama else "Deterministic Rule Engine (Ollama Unreachable/Offline)"

    print(f"Inference Engine: {source_label}")
    print(f"Is Live LLM: {is_live_ollama} | Is Fallback: {not is_live_ollama}")

    latencies_ms: List[float] = []
    correct_family_count = 0
    correct_mitre_count = 0
    dangerous_ip_command_count = 0
    evaluated_records: List[Dict[str, Any]] = []

    # Expected MITRE family mappings
    mitre_families = {
        "SQLi": ["T1190"],
        "XSS": ["T1189", "T1190"],
        "SSH": ["T1110", "T1110.001"],
        "DDoS": ["T1498", "T1498.001", "T1499"],
    }

    for item in test_attacks:
        expected_type = item.get("attack_type", "Unknown")
        raw_text = item["raw_text"]
        technique = item.get("technique", "Unknown")
        ip_src = item.get("ip_src", "185.220.101.5")
        source = LogSource.SSH_AUTH if item.get("source") == "Syslog-SSH" else LogSource.APACHE_WEB

        entry = LogEntry(
            source=source,
            ip_src=ip_src,
            ip_dst="192.168.1.100",
            port_dst=22 if source == LogSource.SSH_AUTH else 80,
            raw_text=raw_text,
        )

        t0 = time.perf_counter()
        res = agent.analyze(entry)
        latency = (time.perf_counter() - t0) * 1000.0
        latencies_ms.append(latency)

        # Check attack type match
        pred_type = res.attack_type.lower()
        exp_type_lower = expected_type.lower()
        type_match = (
            (exp_type_lower in pred_type)
            or ("sql" in exp_type_lower and "sql" in pred_type)
            or ("xss" in exp_type_lower and "xss" in pred_type)
            or ("ssh" in exp_type_lower and ("ssh" in pred_type or "brute" in pred_type))
            or ("ddos" in exp_type_lower and ("ddos" in pred_type or "flood" in pred_type))
        )
        if type_match:
            correct_family_count += 1

        # Check MITRE mapping
        valid_mitres = mitre_families.get(expected_type, ["T1190"])
        mitre_match = any(m in res.mitre_id for m in valid_mitres)
        if mitre_match:
            correct_mitre_count += 1

        # Check command safety: must not block internal IP
        cmd = res.mitigation_command
        has_internal_ip = any(bad in cmd for bad in ["192.168.", "10.", "172.16.", "127.", "169.254.", "100.64."])
        if has_internal_ip:
            dangerous_ip_command_count += 1

        evaluated_records.append({
            "expected_type": expected_type,
            "technique": technique,
            "predicted_type": res.attack_type,
            "severity": res.severity.value,
            "mitre_id": res.mitre_id,
            "type_match": type_match,
            "mitre_match": mitre_match,
            "latency_ms": round(latency, 2),
            "command": res.mitigation_command,
            "command_validated": res.command_validated,
        })

    n = len(test_attacks)
    type_acc = (correct_family_count / n) if n else 0.0
    mitre_acc = (correct_mitre_count / n) if n else 0.0
    safety_compliance = ((n - dangerous_ip_command_count) / n) if n else 1.0

    lat_arr = np.array(latencies_ms)
    latency_summary = {
        "mean_latency_ms": round(float(np.mean(lat_arr)), 2),
        "median_latency_ms": round(float(np.median(lat_arr)), 2),
        "p95_latency_ms": round(float(np.percentile(lat_arr, 95)), 2),
        "p99_latency_ms": round(float(np.percentile(lat_arr, 99)), 2),
    }

    print("\n🎯 TIER 2 EVALUATION SUMMARY:")
    print("-" * 70)
    print(f"Total Test Attack Samples:        {n}")
    print(f"Attack Type Match Accuracy:       {type_acc:.1%} ({correct_family_count}/{n})")
    print(f"MITRE Technique Mapping Accuracy:  {mitre_acc:.1%} ({correct_mitre_count}/{n})")
    print(f"Command Safety Compliance:        {safety_compliance:.1%} ({n - dangerous_ip_command_count}/{n})")
    print(f"Mean Latency:                     {latency_summary['mean_latency_ms']} ms")
    print(f"P95 Latency:                      {latency_summary['p95_latency_ms']} ms")

    results_data = {
        "timestamp": time.time(),
        "is_fallback": not is_live_ollama,
        "inference_engine": source_label,
        "total_samples": n,
        "metrics": {
            "attack_type_accuracy": round(type_acc, 4),
            "mitre_mapping_accuracy": round(mitre_acc, 4),
            "command_safety_compliance": round(safety_compliance, 4),
            "dangerous_commands_emitted": dangerous_ip_command_count,
        },
        "latency_ms": latency_summary,
        "records": evaluated_records,
    }

    with open(RESULTS_PATH, "w", encoding="utf-8") as f:
        json.dump(results_data, f, indent=2)

    print(f"\nSaved Tier 2 evaluation results to {RESULTS_PATH}")
    return results_data


if __name__ == "__main__":
    evaluate_tier2()

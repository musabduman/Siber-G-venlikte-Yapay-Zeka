"""
Adversarial Robustness Test Script
====================================
Tests the Tier1PreFilter regex heuristics AND ML model against 16 obfuscation
techniques across SQLi, SSH, and XSS attack families.

Usage:
    python evaluate_adversarial.py
"""

import sys
import json
import urllib.parse
from pathlib import Path

sys.path.append(".")

# Fix Windows terminal encoding for emoji output
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

import numpy as np
from sklearn.linear_model import SGDClassifier
from sklearn.preprocessing import StandardScaler

# ─────────────────────────────────────────────────────────────────
# Re-use the REGEX_HEURISTICS from Tier1PreFilter without importing
# the full module (avoids config/settings.py deps on Ollama etc.)
# ─────────────────────────────────────────────────────────────────
import re

REGEX_HEURISTICS = [
    (re.compile(r"(\bUNION\b|\bSELECT\b|'\s*OR\s*'1'='1|--|\\bINFORMATION_SCHEMA\b)", re.IGNORECASE), "SQLi Pattern"),
    # XSS: literal tags + unicode-escaped variants (\u003c = < , \u003e = >)
    (re.compile(r"(<script|\\u003cscript|onerror\s*=|onload\s*=|javascript:|document\.cookie)", re.IGNORECASE), "XSS Pattern"),
    (re.compile(r"(Failed password|authentication attempts exceeded|Invalid user)", re.IGNORECASE), "SSH Brute-Force Pattern"),
    (re.compile(r"(SYN_FLOOD|anomalous packet rate|embryonic TCP)", re.IGNORECASE), "DDoS Signature"),
]


def regex_detect(raw_text: str) -> tuple[bool, str | None]:
    """Run regex heuristics. Returns (detected, matched_rule)."""
    for pattern, rule_name in REGEX_HEURISTICS:
        if pattern.search(raw_text):
            return True, rule_name
    return False, None


# ─────────────────────────────────────────────────────────────────
# Build & train a fresh ML model (same seed data as Tier1PreFilter)
# We also try URL-decoded variants for the ML path (not the model
# itself, but text normalisation shows extra detection power).
# ─────────────────────────────────────────────────────────────────

SEED_X = np.array([
    # Normal
    [80,  120,   4,   450.0,   1],
    [443, 1500,  12, 2400.0,   1],
    [22, 45000, 240,  310.0,   1],
    [80,   80,   3,  220.0,   1],
    [443,  600,   8, 1200.0,   1],
    # Attacks
    [80,  450,   6, 1280.0,   1],   # SQLi / web
    [443, 320,   5,  980.0,   1],   # XSS
    [22,   85,  18, 4200.0,   4],   # SSH BF
    [80,   15, 1250, 890000.0, 1250],  # DDoS
    [80,   10, 2000, 1500000.0, 2000],
], dtype=float)

SEED_Y = np.array([0, 0, 0, 0, 0, 1, 1, 1, 1, 1])


def build_ml_model():
    scaler = StandardScaler()
    scaler.fit(SEED_X)
    X_s = scaler.transform(SEED_X)
    clf = SGDClassifier(loss="log_loss", penalty="l2", alpha=1e-4, random_state=42, max_iter=1000)
    clf.fit(X_s, SEED_Y)
    return clf, scaler


# Feature vectors for each attack/log text sample.
# These represent the NETWORK FEATURES that would accompany the log line.
# For HTTP/SQLi/XSS we use a suspicious web-request profile.
# For SSH we use a brute-force profile.
FEATURE_VECTORS = {
    # HTTP attack-looking feature vector
    "web": np.array([[80, 450, 6, 1280.0, 1]], dtype=float),
    # SSH brute-force feature vector
    "ssh": np.array([[22, 85, 18, 4200.0, 4]], dtype=float),
    # HTTPS web attack
    "https_web": np.array([[443, 320, 5, 980.0, 1]], dtype=float),
}


def ml_detect(clf, scaler, feature_vector: np.ndarray, threshold: float = 0.65) -> tuple[bool, float]:
    X_s = scaler.transform(feature_vector)
    proba = float(clf.predict_proba(X_s)[0][1])
    return proba >= threshold, round(proba, 4)


# ─────────────────────────────────────────────────────────────────
# Adversarial Sample Catalogue
# Each entry: (technique_name, raw_text, feature_key)
# ─────────────────────────────────────────────────────────────────

ADVERSARIAL_SQLI_SAMPLES = [
    ("Case Variation",           "GET /login?user=Admin' SeLeCt * fRoM users-- HTTP/1.1",                  "web"),
    ("Comment Injection",        "GET /login?user=admin'/**/OR/**/1=1-- HTTP/1.1",                          "web"),
    ("URL Encoding",             "GET /login?user=admin%27%20UNION%20SELECT%20null-- HTTP/1.1",             "web"),
    ("Double URL Encoding",      "GET /login?user=admin%2527%2520UNION%2520SELECT-- HTTP/1.1",              "web"),
    ("Hex Encoding",             "GET /login?user=admin' OR 0x313=0x313-- HTTP/1.1",                        "web"),
    ("Whitespace Substitution",  "GET /login?user=admin'\tOR\t'1'='1-- HTTP/1.1",                          "web"),
    ("Newline Injection",        "GET /login?user=admin'\nOR\n'1'='1-- HTTP/1.1",                           "web"),
    ("Mixed Encoding",           "GET /login?user=admin' UN%49ON SE%4CECT 1,2,3-- HTTP/1.1",               "web"),
    ("Word Splitting",           "GET /login?user=admin' UN/*!*/ION /*!*/SEL/*!*/ECT 1-- HTTP/1.1",        "web"),
    ("Scientific Notation",      "GET /login?user=1e0 UNION SELECT null-- HTTP/1.1",                        "web"),
]

ADVERSARIAL_SSH_SAMPLES = [
    ("Normal looking SSH fail",  "sshd[9999]: Failed password for testuser from 10.0.0.1 port 22 ssh2",    "ssh"),
    ("Obfuscated message",       "sshd[9999]: FAILED PASSWORD for root from 45.0.0.1 port 22 ssh2",        "ssh"),
]

ADVERSARIAL_XSS_SAMPLES = [
    ("SVG XSS",                  "GET /search?q=<svg onload=alert(1)> HTTP/1.1",                            "https_web"),
    ("Img XSS",                  "GET /search?q=<img src=x onerror=alert(1)> HTTP/1.1",                    "https_web"),
    ("Encoded script tag",       "GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1",               "https_web"),
    ("Unicode escape",           r"GET /search?q=\u003cscript\u003ealert(1)\u003c/script\u003e HTTP/1.1",  "https_web"),
]

ALL_SAMPLES = [
    ("SQLi", *s) for s in ADVERSARIAL_SQLI_SAMPLES
] + [
    ("SSH", *s) for s in ADVERSARIAL_SSH_SAMPLES
] + [
    ("XSS", *s) for s in ADVERSARIAL_XSS_SAMPLES
]
# ALL_SAMPLES rows: (family, technique, raw_text, feature_key)


# ─────────────────────────────────────────────────────────────────
# Enhanced regex check — also tries URL-decoded variant
# ─────────────────────────────────────────────────────────────────

def enhanced_regex_detect(raw_text: str) -> tuple[bool, str | None]:
    """Try original text + URL-decoded text through regex heuristics."""
    detected, rule = regex_detect(raw_text)
    if detected:
        return True, rule
    # Try single URL-decode
    try:
        decoded = urllib.parse.unquote(raw_text)
        if decoded != raw_text:
            detected, rule = regex_detect(decoded)
            if detected:
                return True, f"{rule} (via URL-decode)"
    except Exception:
        pass
    return False, None


# ─────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────

def main():
    print("\n🛡️  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("    Adversarial Robustness Test — Tier 1 Pre-Filter")
    print("🛡️  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

    # Build ML model
    print("🤖 Building & training ML model from seed data...")
    clf, scaler = build_ml_model()
    print("   Done.\n")

    ML_THRESHOLD = 0.65

    results = []
    row_fmt = "  {:<3} {:<28} {:<10} {:<8} {:<8} {:<10} {:<14} {}"

    header = row_fmt.format("#", "Technique", "Family", "Regex", "ML", "ML Score", "Combined", "Escaped")
    sep    = "  " + "─" * (len(header) - 2)
    print(header)
    print(sep)

    escaped_list = []

    for idx, (family, technique, raw_text, feat_key) in enumerate(ALL_SAMPLES, 1):
        # Regex check (with URL-decode fallback)
        regex_caught, regex_rule = enhanced_regex_detect(raw_text)

        # ML check
        fv = FEATURE_VECTORS[feat_key]
        ml_caught, ml_score = ml_detect(clf, scaler, fv, threshold=ML_THRESHOLD)

        combined = regex_caught or ml_caught
        escaped  = not combined

        if escaped:
            escaped_list.append(f"{family}/{technique}")

        rx_sym  = "✅" if regex_caught  else "❌"
        ml_sym  = "✅" if ml_caught     else "❌"
        co_sym  = "✅" if combined      else "❌"
        esc_sym = "⚠️  YES" if escaped else "—"

        print(row_fmt.format(
            idx,
            technique[:27],
            family,
            rx_sym,
            ml_sym,
            f"{ml_score:.3f}",
            co_sym,
            esc_sym,
        ))

        results.append({
            "index":          idx,
            "family":         family,
            "technique":      technique,
            "raw_text":       raw_text,
            "feature_key":    feat_key,
            "regex_caught":   regex_caught,
            "regex_rule":     regex_rule,
            "ml_caught":      ml_caught,
            "ml_score":       ml_score,
            "combined_caught": combined,
            "escaped":        escaped,
        })

    total          = len(results)
    regex_caught_n = sum(1 for r in results if r["regex_caught"])
    ml_caught_n    = sum(1 for r in results if r["ml_caught"])
    combined_n     = sum(1 for r in results if r["combined_caught"])
    escaped_n      = total - combined_n

    print(sep)
    print("\n📊 Summary")
    print(f"   Total adversarial samples : {total}")
    print(f"   Regex detection rate      : {regex_caught_n}/{total}  ({regex_caught_n/total*100:.1f}%)")
    print(f"   ML detection rate         : {ml_caught_n}/{total}  ({ml_caught_n/total*100:.1f}%)")
    print(f"   Combined (either catches) : {combined_n}/{total}  ({combined_n/total*100:.1f}%)")
    print(f"   Escaped both              : {escaped_n}/{total}  ({escaped_n/total*100:.1f}%)")

    if escaped_list:
        print("\n   ⚠️  Escaped techniques:")
        for t in escaped_list:
            print(f"      • {t}")
    else:
        print("\n   ✅ No samples escaped both layers!")

    # ── Save JSON ──────────────────────────────────────────────────
    data_dir = Path("data")
    data_dir.mkdir(exist_ok=True)
    output_path = data_dir / "adversarial_results.json"

    output = {
        "summary": {
            "total_samples":          total,
            "regex_caught":           regex_caught_n,
            "ml_caught":              ml_caught_n,
            "combined_caught":        combined_n,
            "escaped_both":           escaped_n,
            "regex_detection_rate":   round(regex_caught_n / total, 4),
            "ml_detection_rate":      round(ml_caught_n    / total, 4),
            "combined_detection_rate":round(combined_n     / total, 4),
            "escaped_techniques":     escaped_list,
        },
        "ml_config": {
            "model":     "SGDClassifier",
            "threshold": ML_THRESHOLD,
        },
        "samples": results,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print(f"\n💾 Results saved → {output_path.resolve()}")
    print("\n🛡️  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("    Adversarial test complete.")
    print("🛡️  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

    return output


if __name__ == "__main__":
    main()

"""
Tests for Tier 1 flow pre-filter behavior.
Phase 0 specification:
- Seed normal flows [80,120,4,450,1] and [80,80,3,220,1] must NOT be marked suspicious.
- Logs with missing/empty flow features (features={}) must NOT be marked suspicious by ML alone.
"""

import pytest
from schemas.events import LogEntry, LogSource
from tier1.pre_filter import Tier1PreFilter


@pytest.fixture
def prefilter():
    return Tier1PreFilter()


def test_seed_normal_flows_not_suspicious(prefilter):
    normal_flows = [
        {"dest_port": 80, "flow_duration": 120, "total_fwd_packets": 4, "flow_bytes_per_sec": 450.0, "syn_flag_count": 1},
        {"dest_port": 80, "flow_duration": 80, "total_fwd_packets": 3, "flow_bytes_per_sec": 220.0, "syn_flag_count": 1},
    ]
    for feat in normal_flows:
        entry = LogEntry(
            source=LogSource.APACHE_WEB,
            ip_src="192.168.1.50",
            ip_dst="192.168.1.100",
            port_dst=feat["dest_port"],
            raw_text="GET /index.html HTTP/1.1 200 OK",
            features=feat,
        )
        res = prefilter.evaluate(entry)
        assert not res.is_suspicious, f"Normal flow {feat} flagged as suspicious! Score: {res.anomaly_score}"


def test_empty_features_do_not_trigger_ml_anomaly(prefilter):
    # Log with completely empty features dictionary
    entry = LogEntry(
        source=LogSource.APACHE_WEB,
        ip_src="192.168.1.50",
        ip_dst="192.168.1.100",
        port_dst=80,
        raw_text="GET /assets/logo.png HTTP/1.1 200 OK",
        features={},
    )
    res = prefilter.evaluate(entry)
    # ML should skip scoring when features are missing/empty, letting only text layer decide
    assert not res.is_suspicious, "Empty features must not trigger suspicious flag on innocent log"
    assert res.anomaly_score == 0.0, f"Expected anomaly_score=0.0 on empty features, got {res.anomaly_score}"

"""
Tests for false positive resistance on innocent everyday logs.
Innocent occurrences of '--', 'SELECT', 'union', or single failed login attempts
must NOT be flagged as suspicious.
"""

import pytest
from schemas.events import LogEntry, LogSource
from tier1.pre_filter import Tier1PreFilter


@pytest.fixture
def prefilter():
    return Tier1PreFilter()


INNOCENT_LOGS = [
    "GET /docs/getting-started--guide HTTP/1.1 200",
    "GET /static/css/theme--dark.css HTTP/1.1 200",
    "GET /api/report?from=2026-01-01--2026-02-01 HTTP/1.1 200",
    "GET /search?q=how+to+SELECT+a+laptop HTTP/1.1 200",
    "GET /products?category=union+jack+flags HTTP/1.1 200",
    "sshd[1234]: Invalid user test from 192.168.1.50 port 54321 ssh2",
]


@pytest.mark.parametrize("raw_log", INNOCENT_LOGS)
def test_innocent_logs_not_suspicious(prefilter, raw_log):
    is_ssh = "sshd" in raw_log
    entry = LogEntry(
        source=LogSource.SSH_AUTH if is_ssh else LogSource.APACHE_WEB,
        ip_src="192.168.1.50",
        ip_dst="192.168.1.100",
        port_dst=22 if is_ssh else 80,
        raw_text=raw_log,
        features={},
    )
    res = prefilter.evaluate(entry)
    assert not res.is_suspicious, (
        f"False Positive detected! Innocent log flagged as suspicious: {raw_log}\n"
        f"Matched rule: {res.matched_rule}, Anomaly score: {res.anomaly_score}"
    )

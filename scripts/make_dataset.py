"""
Synthetic Dataset Generator for Tier 1 Flow Model (CIC-IDS2017-like).
Deterministic generation (seed=42).
Clearly identified as SYNTHETIC, CIC-IDS2017-like flow data.
"""

import csv
from pathlib import Path
import random
import numpy as np

RANDOM_SEED = 42
random.seed(RANDOM_SEED)
np.random.seed(RANDOM_SEED)

OUTPUT_PATH = Path(__file__).resolve().parent.parent / "data" / "synthetic_cic_flows.csv"


def generate_dataset(num_benign=800, num_attacks_per_class=120):
    """
    Generates a balanced dataset of synthetic flows with realistic port and traffic distributions.
    Features:
    - dest_port: raw port
    - flow_duration: duration in ms
    - total_fwd_packets: packet count
    - flow_bytes_per_sec: bytes / sec
    - syn_flag_count: syn flag count
    - label: 0 for BENIGN, 1 for Attack
    - attack_type: text label
    """
    rows = []

    # 1. BENIGN flows (web, dns, ssh, db, background)
    web_ports = [80, 443, 8080]
    dns_ports = [53]
    db_ports = [3306, 5432]
    ssh_ports = [22]
    other_ports = [21, 25, 110, 8443, 5000]

    for _ in range(num_benign):
        ptype = random.choices(["web_light", "web_standard", "web_large", "dns", "db", "ssh", "other"],
                               weights=[0.35, 0.25, 0.10, 0.10, 0.08, 0.08, 0.04])[0]
        if ptype == "web_light":
            # Lightweight web requests (e.g. GET /index.html, CSS, pings: [80, 120, 4, 450, 1])
            port = random.choice(web_ports)
            dur = max(20, int(np.random.normal(loc=120, scale=40)))
            fwd = max(2, int(np.random.poisson(lam=3.5)))
            bytes_sec = max(100.0, float(np.random.normal(loc=350.0, scale=120.0)))
            syn = 1
        elif ptype == "web_standard":
            port = random.choice(web_ports)
            dur = max(100, int(np.random.normal(loc=650, scale=200)))
            fwd = max(5, int(np.random.poisson(lam=10)))
            bytes_sec = max(300.0, float(np.random.normal(loc=1500.0, scale=400.0)))
            syn = 1
        elif ptype == "web_large":
            port = random.choice(web_ports)
            dur = max(500, int(np.random.exponential(scale=2500)))
            fwd = max(15, int(np.random.poisson(lam=35)))
            bytes_sec = max(1500.0, float(np.random.normal(loc=5000.0, scale=1500.0)))
            syn = 1
        elif ptype == "dns":
            port = 53
            dur = max(2, int(np.random.exponential(scale=30)))
            fwd = random.randint(1, 3)
            bytes_sec = max(20.0, float(np.random.normal(loc=250.0, scale=50.0)))
            syn = 0
        elif ptype == "db":
            port = random.choice(db_ports)
            dur = max(50, int(np.random.exponential(scale=1500)))
            fwd = max(5, int(np.random.poisson(lam=15)))
            bytes_sec = max(100.0, float(np.random.normal(loc=3000.0, scale=800.0)))
            syn = 1
        elif ptype == "ssh":
            port = 22
            dur = max(5000, int(np.random.exponential(scale=30000)))  # Long interactive sessions
            fwd = max(20, int(np.random.poisson(lam=120)))
            bytes_sec = max(30.0, float(np.random.normal(loc=350.0, scale=100.0)))
            syn = 1
        else:
            port = random.choice(other_ports)
            dur = max(100, int(np.random.exponential(scale=1000)))
            fwd = random.randint(2, 10)
            bytes_sec = max(50.0, float(np.random.normal(loc=500.0, scale=150.0)))
            syn = 1

        rows.append([port, dur, fwd, round(bytes_sec, 2), syn, 0, "BENIGN"])

    # 2. SQL Injection / Web Exploit flows (anomalous: automated scans, exfiltration, or time delays)
    for _ in range(num_attacks_per_class):
        port = random.choice(web_ports)
        variant = random.choice(["scan_burst", "time_delay", "exfiltration"])
        if variant == "scan_burst":
            # Rapid scanner probe (nikto/sqlmap)
            dur = random.randint(50, 400)
            fwd = random.randint(15, 45)
            bytes_sec = max(3000.0, float(np.random.normal(loc=8500.0, scale=2000.0)))
            syn = random.randint(2, 4)
        elif variant == "time_delay":
            # Blind time-based SQL injection (SLEEP / BENCHMARK delay)
            dur = random.randint(4500, 15000)
            fwd = random.randint(4, 10)
            bytes_sec = max(30.0, float(np.random.normal(loc=120.0, scale=40.0)))
            syn = 1
        else:
            # Data exfiltration dump
            dur = random.randint(1000, 6000)
            fwd = random.randint(40, 120)
            bytes_sec = max(20000.0, float(np.random.normal(loc=65000.0, scale=15000.0)))
            syn = 1
        rows.append([port, dur, fwd, round(bytes_sec, 2), syn, 1, "SQL_Injection"])

    # 3. Port Scan / Reconnaissance
    for _ in range(num_attacks_per_class):
        port = random.choice([21, 23, 25, 80, 135, 443, 445, 1433, 3306, 3389, 8080])
        dur = random.randint(1, 25)
        fwd = random.randint(1, 3)
        bytes_sec = max(10.0, float(np.random.normal(loc=50.0, scale=20.0)))
        syn = random.randint(2, 4)  # Repeated probes
        rows.append([port, dur, fwd, round(bytes_sec, 2), syn, 1, "Port_Scan"])

    # 4. SSH Brute Force (rapid failed auth attempts, high SYN count, short bursts)
    for _ in range(num_attacks_per_class):
        port = 22
        dur = random.randint(20, 180)  # Very short bursts compared to normal sessions
        fwd = random.randint(15, 50)
        bytes_sec = max(1500.0, float(np.random.normal(loc=6500.0, scale=1500.0)))
        syn = random.randint(3, 10)  # Multiple SYNs per short window
        rows.append([port, dur, fwd, round(bytes_sec, 2), syn, 1, "SSH_Brute_Force"])

    # 5. DDoS (massive packet and byte rates, huge SYN flags)
    for _ in range(num_attacks_per_class):
        port = random.choice([80, 443, 53, 8080])
        dur = random.randint(5, 30)
        fwd = random.randint(1000, 3000)
        bytes_sec = max(200000.0, float(np.random.normal(loc=950000.0, scale=150000.0)))
        syn = fwd
        rows.append([port, dur, fwd, round(bytes_sec, 2), syn, 1, "DDoS"])

    random.shuffle(rows)

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["dest_port", "flow_duration", "total_fwd_packets", "flow_bytes_per_sec", "syn_flag_count", "label", "attack_type"])
        writer.writerows(rows)

    print(f"Generated {len(rows)} synthetic CIC-IDS2017-like records -> {OUTPUT_PATH}")
    return OUTPUT_PATH


if __name__ == "__main__":
    generate_dataset()

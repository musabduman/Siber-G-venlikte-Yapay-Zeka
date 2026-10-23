"""
Log Streamer & Traffic Simulator (Tier 0).
Simulates real-time multi-source enterprise logs (CIC-IDS2017 flow data, Apache web, SSH auth)
with periodic attack injection into an asynchronous Queue.
"""

from datetime import datetime
import json
import logging
import queue
import random
import threading
import time
from typing import Generator, List, Optional

from config.settings import settings
from schemas.events import LogEntry, LogSource

logger = logging.getLogger("AI_SOC.LogStreamer")


class LogStreamer:
    def __init__(
        self,
        event_queue: Optional[queue.Queue] = None,
        attack_rate: float = 0.15,
        logs_per_second: int = 5,
    ):
        """
        :param event_queue: Thread-safe queue to push generated LogEntry objects.
        :param attack_rate: Probability [0.0 - 1.0] of injecting an attack in random stream.
        :param logs_per_second: Streaming throughput.
        """
        self.queue: queue.Queue = event_queue if event_queue is not None else queue.Queue(maxsize=1000)
        self.attack_rate: float = attack_rate
        self.logs_per_second: int = logs_per_second
        self.is_running: bool = False
        self._thread: Optional[threading.Thread] = None

        # Load payload datasets
        self.attack_catalog = self._load_json(settings.DATA_DIR / "attack_payloads.json").get("attacks", [])
        self.normal_catalog = self._load_json(settings.DATA_DIR / "normal_logs.json").get("normal_traffic", [])

        # Internal IP pools
        self.attacker_ips = [
            "185.220.101.5",
            "45.142.120.19",
            "194.26.29.112",
            "103.251.167.20",
            "91.240.118.172",
        ]
        self.internal_ips = [
            "192.168.1.15",
            "192.168.1.42",
            "10.0.0.55",
            "172.16.0.8",
            "192.168.1.105",
        ]

    def _load_json(self, path) -> dict:
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Could not load dataset from {path}: {e}")
            return {}

    def generate_single_log(self, force_attack_type: Optional[str] = None) -> LogEntry:
        """Generates one standardized LogEntry (either normal or attack)."""
        is_attack = force_attack_type is not None or (random.random() < self.attack_rate)

        if is_attack and self.attack_catalog:
            if force_attack_type:
                matches = [a for a in self.attack_catalog if force_attack_type.lower() in a["type"].lower()]
                category = matches[0] if matches else random.choice(self.attack_catalog)
            else:
                category = random.choice(self.attack_catalog)

            template = random.choice(category["templates"])
            src_ip = random.choice(self.attacker_ips)
            src_port = random.randint(32000, 65000)
            raw_text = template.format(src_ip=src_ip, src_port=src_port)
            source = LogSource(category["source"])
            port_dst = category.get("port", 80)
            protocol = category.get("protocol", "TCP")
            features = dict(category.get("flow_features", {}))
            features["label"] = 1  # 1 for malicious
            features["attack_type"] = category["type"]
        else:
            category = random.choice(self.normal_catalog) if self.normal_catalog else {
                "source": "Apache-HTTP",
                "port": 80,
                "protocol": "TCP",
                "templates": ["GET /api/v1/health HTTP/1.1 200 OK"],
                "flow_features": {"dest_port": 80, "flow_duration": 100, "total_fwd_packets": 3, "flow_bytes_per_sec": 300.0, "syn_flag_count": 1}
            }
            template = random.choice(category["templates"])
            src_ip = random.choice(self.internal_ips)
            src_port = random.randint(40000, 60000)
            raw_text = template.format(src_ip=src_ip, src_port=src_port)
            source = LogSource(category["source"])
            port_dst = category.get("port", 80)
            protocol = category.get("protocol", "TCP")
            features = dict(category.get("flow_features", {}))
            features["label"] = 0  # 0 for normal

        return LogEntry(
            timestamp=datetime.utcnow(),
            source=source,
            ip_src=src_ip,
            ip_dst="192.168.1.100",
            port_dst=port_dst,
            protocol=protocol,
            raw_text=raw_text,
            features=features,
        )

    def inject_manual_attack(self, attack_type: str) -> LogEntry:
        """Injects a targeted attack directly into the queue for live jury demonstration."""
        entry = self.generate_single_log(force_attack_type=attack_type)
        try:
            self.queue.put_nowait(entry)
            logger.info(f"Manual attack injected: {attack_type} from {entry.ip_src}")
        except queue.Full:
            logger.warning("Event queue full; dropped manual attack log.")
        return entry

    def _stream_worker(self):
        """Background thread target that feeds logs into the queue."""
        sleep_interval = 1.0 / max(self.logs_per_second, 1)
        while self.is_running:
            entry = self.generate_single_log()
            try:
                self.queue.put(entry, timeout=0.5)
            except queue.Full:
                pass
            time.sleep(sleep_interval)

    def start(self):
        """Starts asynchronous background streaming."""
        if not self.is_running:
            self.is_running = True
            self._thread = threading.Thread(target=self._stream_worker, daemon=True, name="LogStreamerWorker")
            self._thread.start()
            logger.info(f"LogStreamer started with {self.logs_per_second} logs/sec, attack_rate={self.attack_rate}")

    def stop(self):
        """Stops background streaming."""
        self.is_running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)
            logger.info("LogStreamer stopped.")

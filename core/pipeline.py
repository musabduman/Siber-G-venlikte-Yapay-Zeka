"""
Central SOC Processing Pipeline & Continual Learning Orchestrator.
Threaded & Asynchronous: Moves AI inference and ML evaluation to a background thread
so the user interface remains 100% responsive without UI freezing or locking.
"""

from collections import deque
import logging
import queue
import threading
import time
from typing import Any, Deque, Dict, List, Optional, Tuple

from config.settings import settings
from core.log_streamer import LogStreamer
from memory.vector_store import VectorMemory
from schemas.events import LogEntry, ThreatAnalysisResult, Tier1Result
from tier1.pre_filter import Tier1PreFilter
from tier2.cisco_agent import CiscoThreatAgent

logger = logging.getLogger("AI_SOC.Pipeline")


class SOCPipeline:
    def __init__(
        self,
        streamer: Optional[LogStreamer] = None,
        pre_filter: Optional[Tier1PreFilter] = None,
        cisco_agent: Optional[CiscoThreatAgent] = None,
        vector_memory: Optional[VectorMemory] = None,
    ):
        self.streamer = streamer or LogStreamer()
        self.pre_filter = pre_filter or Tier1PreFilter()
        self.memory = vector_memory or VectorMemory()
        self.cisco_agent = cisco_agent or CiscoThreatAgent(memory=self.memory)

        # Thread synchronization
        self._lock = threading.Lock()
        self._is_running: bool = False
        self._worker_thread: Optional[threading.Thread] = None

        # In-memory incident registries for live UI (thread-safe deques)
        self.recent_logs: Deque[Tuple[LogEntry, Tier1Result]] = deque(maxlen=200)
        self.active_threats: Deque[Tuple[LogEntry, ThreatAnalysisResult]] = deque(maxlen=50)
        self.log_history_map: Dict[str, Tuple[LogEntry, Optional[ThreatAnalysisResult]]] = {}
        self.incident_ledger: List[Dict[str, Any]] = []

        # Enterprise SOC Metrics
        self.total_inspected_logs: int = 0
        self.total_blocked_attacks: int = 0
        self.learned_threats_count: int = 0
        self.last_update_latency_ms: float = 0.0

    @property
    def gpu_status(self) -> str:
        """Returns Idle vs Active status for RTX 4050 dashboard."""
        return "ACTIVE (Inference)" if self.cisco_agent.is_gpu_active else "IDLE (Power Save)"

    def start_stream(self):
        """Starts both traffic streamer and asynchronous background pipeline worker."""
        if not self._is_running:
            self._is_running = True
            self.streamer.start()
            self._worker_thread = threading.Thread(
                target=self._background_pipeline_worker,
                daemon=True,
                name="AsyncPipelineWorker"
            )
            self._worker_thread.start()
            logger.info("Pipeline background worker thread started.")

    def stop_stream(self):
        """Stops background worker and streamer."""
        self._is_running = False
        self.streamer.stop()
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=1.0)
            logger.info("Pipeline background worker stopped.")

    def inject_manual_simulation(self, attack_type: str) -> LogEntry:
        """Pushes manual simulation directly into the processing queue."""
        entry = self.streamer.inject_manual_attack(attack_type)
        # If stream is paused, process it immediately in a dedicated thread
        if not self._is_running:
            threading.Thread(target=self._process_single_entry, args=(entry,), daemon=True).start()
        return entry

    def _background_pipeline_worker(self):
        """Dedicated background thread continuously processing queued logs."""
        while self._is_running:
            try:
                entry = self.streamer.queue.get(timeout=0.2)
                self._process_single_entry(entry)
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Error in background pipeline worker: {e}")

    def _process_single_entry(self, entry: LogEntry):
        """Evaluates Tier 1 on CPU; if suspicious, calls Tier 2 LLM in parallel."""
        # Tier 1 Rapid Filter (< 1ms CPU)
        t1_result = self.pre_filter.evaluate(entry)
        t2_result: Optional[ThreatAnalysisResult] = None

        if t1_result.is_suspicious:
            # Escalation to Tier 2 Cisco LLM (Ollama)
            t2_result = self.cisco_agent.analyze(entry)

        with self._lock:
            self.total_inspected_logs += 1
            if t1_result.is_suspicious and t2_result is not None:
                self.total_blocked_attacks += 1
                self.active_threats.appendleft((entry, t2_result))
                self.incident_ledger.insert(0, {
                    "id": entry.id,
                    "timestamp": entry.timestamp,
                    "entry": entry,
                    "analysis": t2_result,
                    "status": "Değerlendirilmemiş",
                    "reviewed_at": None,
                })
                if len(self.incident_ledger) > 100:
                    self.incident_ledger.pop()

            self.recent_logs.appendleft((entry, t1_result))
            self.log_history_map[entry.id] = (entry, t2_result)

    def process_one_log(self, entry: Optional[LogEntry] = None) -> Optional[Tuple[LogEntry, Tier1Result, Optional[ThreatAnalysisResult]]]:
        """Synchronous helper for tests."""
        if entry is None:
            try:
                entry = self.streamer.queue.get_nowait()
            except queue.Empty:
                return None
        self._process_single_entry(entry)
        with self._lock:
            rec = self.log_history_map.get(entry.id)
            if rec:
                return rec[0], self.recent_logs[0][1], rec[1]
        return None

    def get_snapshot(self) -> Dict[str, Any]:
        """Returns a thread-safe snapshot of metrics and recent incident collections."""
        with self._lock:
            return {
                "total_inspected_logs": self.total_inspected_logs,
                "total_blocked_attacks": self.total_blocked_attacks,
                "learned_threats_count": self.learned_threats_count,
                "last_update_latency_ms": self.last_update_latency_ms,
                "gpu_status": self.gpu_status,
                "recent_logs": list(self.recent_logs),
                "active_threats": list(self.active_threats),
                "incident_ledger": list(self.incident_ledger),
                "memory_count": self.memory.get_total_memory_count()
            }

    def reset_all(self):
        """Complete reset of all pipeline metrics, history, ChromaDB, and ML model."""
        with self._lock:
            self.stop_stream()
            # Drain queue
            while not self.streamer.queue.empty():
                try:
                    self.streamer.queue.get_nowait()
                except Exception:
                    break
            self.recent_logs.clear()
            self.active_threats.clear()
            self.incident_ledger.clear()
            self.log_history_map.clear()
            self.total_inspected_logs = 0
            self.total_blocked_attacks = 0
            self.learned_threats_count = 0
            self.last_update_latency_ms = 0.0

        self.memory.reset_memory()
        self.pre_filter.reset_model()
        logger.info("Complete pipeline reset performed.")

    def submit_feedback(self, log_id: str, is_true_attack: bool, corrected_attack_type: Optional[str] = None) -> Dict[str, Any]:
        """
        Continual Learning Feedback Loop (Stage 5):
        - Updates ChromaDB RAG vector memory if verified as genuine threat.
        - Triggers online partial_fit on CPU SGDClassifier model in milliseconds.
        """
        with self._lock:
            record = self.log_history_map.get(log_id)

        if not record:
            return {"success": False, "message": "Log ID bulunamadı."}

        entry, analysis = record

        # 1. Update ML Pre-Filter via partial_fit
        update_ms = self.pre_filter.update_model_online(entry, is_true_attack=is_true_attack)

        with self._lock:
            # Remove the resolved incident from active queue so it disappears from the dashboard
            self.active_threats = deque([item for item in self.active_threats if item[0].id != log_id], maxlen=50)
            self.last_update_latency_ms = update_ms
            self.learned_threats_count += 1

            # Update status in permanent audit ledger
            new_status = "Doğrulandı" if is_true_attack else "Tehdit Değil"
            for inc in self.incident_ledger:
                if inc["id"] == log_id:
                    inc["status"] = new_status
                    inc["reviewed_at"] = time.strftime("%H:%M:%S")
                    break

        # 2. If verified as an attack, persist to ChromaDB vector store
        if is_true_attack and analysis:
            if corrected_attack_type:
                analysis.attack_type = corrected_attack_type
            self.memory.store_verified_incident(
                log_id=entry.id,
                raw_log=entry.raw_text,
                result=analysis
            )

        logger.info(f"Feedback submitted for log {log_id}: is_attack={is_true_attack}, update_time={update_ms}ms")
        return {
            "success": True,
            "learned_count": self.learned_threats_count,
            "update_latency_ms": update_ms,
            "vector_memory_total": self.memory.get_total_memory_count()
        }

"""
Enterprise Data Contracts (Schemas) for AI-Driven SOC Appliance.
Enforces strict typing across all pipeline tiers.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional, Union
import uuid
from pydantic import BaseModel, Field


class LogSource(str, Enum):
    CIC_IDS2017 = "CIC-IDS2017"
    APACHE_WEB = "Apache-HTTP"
    SSH_AUTH = "SSH-Auth"
    MANUAL_INJECTION = "Manual-Simulation"


class ThreatSeverity(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class LogEntry(BaseModel):
    """Normalized ingested log entry."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    source: LogSource = Field(default=LogSource.APACHE_WEB)
    ip_src: str = Field(default="127.0.0.1")
    ip_dst: str = Field(default="192.168.1.100")
    port_dst: int = Field(default=80)
    protocol: str = Field(default="TCP")
    raw_text: str = Field(description="Raw log string or reconstructed request line")
    features: Dict[str, Any] = Field(default_factory=dict, description="Tabular/flow metrics")


class Tier1Result(BaseModel):
    """Output from Tier 1 CPU-only rapid filter."""
    log_id: str
    log_entry: LogEntry
    is_suspicious: bool = Field(description="True if flagged for Tier 2 escalation")
    anomaly_score: float = Field(default=0.0, ge=0.0, le=1.0)
    matched_rule: Optional[str] = None
    processing_time_ms: float = Field(default=0.0)
    feature_contributions: Optional[Dict[str, float]] = None


class ThreatAnalysisResult(BaseModel):
    """
    Output from Tier 2 Cisco LLM Agent.
    Strictly follows the required system schema + pedagogical computer-science explainers.
    """
    log_id: str
    attack_type: str = Field(description="Name of detected attack (e.g. SQL Injection / SSH Brute Force)")
    severity: ThreatSeverity = Field(description="Low / Medium / High / Critical")
    mitre_id: str = Field(description="MITRE ATT&CK technique ID (e.g. T1190)")
    summary: str = Field(description="Single-sentence Turkish technical explanation")
    mitigation_command: str = Field(description="Directly executable Linux iptables or WAF mitigation command")
    raw_llm_response: Optional[str] = None
    latency_ms: float = Field(default=0.0)
    cached_or_rag: bool = Field(default=False)

    # CS-Friendly Explanations (Educational context for non-security specialists)
    cs_explanation: Optional[str] = None
    mitre_name: Optional[str] = None
    command_breakdown: Optional[str] = None
    command_validated: Optional[bool] = None


class HumanFeedback(BaseModel):
    """Feedback payload for continual learning and model updates."""
    log_id: str
    is_true_positive: bool = Field(description="True if actually an attack, False if False Positive")
    corrected_attack_type: Optional[str] = None
    raw_log: str
    analyst_note: Optional[str] = None

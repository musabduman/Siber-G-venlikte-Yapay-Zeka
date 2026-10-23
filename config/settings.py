"""
Centralized Configuration for AI-Driven SOC (Enterprise Architecture).
All sensitive parameters, thresholds, and endpoints are managed here.
"""

from pathlib import Path
from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Base Paths
    BASE_DIR: Path = Path(__file__).resolve().parent.parent
    DATA_DIR: Path = BASE_DIR / "data"
    MODEL_DIR: Path = BASE_DIR / "tier1" / "models"
    CHROMA_PERSIST_DIR: Path = BASE_DIR / "memory" / "chroma_db"

    # Ollama / Cisco LLM Settings
    OLLAMA_BASE_URL: str = Field(
        default="http://localhost:11434",
        description="Local Ollama instance URL"
    )
    OLLAMA_MODEL: str = Field(
        default="Foundation-Sec-8B-Instruct",
        description="Target specialized cybersecurity LLM"
    )
    FALLBACK_MODEL: str = Field(
        default="qwen2.5:1.5b",
        description="Fallback lightweight model if primary is not available"
    )
    LLM_NUM_PREDICT: int = Field(
        default=200,
        description="Token limit to prevent GPU overheating on RTX 4050"
    )
    LLM_TEMPERATURE: float = Field(
        default=0.1,
        description="Low temperature for strictly deterministic threat output"
    )

    # Tier 1 ML Filter Settings
    ML_ANOMALY_THRESHOLD: float = Field(
        default=0.65,
        description="Threshold above which a log is marked as suspicious"
    )
    LOG_STREAM_BATCH_SIZE: int = Field(default=5, description="Logs per tick")
    LOG_STREAM_INTERVAL_SEC: float = Field(default=1.0, description="Seconds between stream ticks")

    # Continual Learning / ChromaDB Settings
    RAG_TOP_K: int = Field(
        default=2,
        description="Number of few-shot cases retrieved for context"
    )
    CHROMA_COLLECTION_NAME: str = Field(
        default="soc_threat_intel",
        description="ChromaDB collection for verified incidents"
    )

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()

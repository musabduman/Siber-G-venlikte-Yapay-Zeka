"""
Alias wrapper for Phase 5 continual learning specification compliance.
Exposes VectorMemory (ChromaDB RAG) and Incremental Learning capabilities.
"""
from memory.vector_store import VectorMemory
from tier1.pre_filter import Tier1PreFilter

__all__ = ["VectorMemory", "Tier1PreFilter"]

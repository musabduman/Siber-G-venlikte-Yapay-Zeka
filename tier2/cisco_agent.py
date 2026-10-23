"""
Tier 2 Deep Threat Analysis Agent (Cisco Foundation-Sec-8B / Local Ollama).
Performs semantic attack verification, MITRE ATT&CK mapping, and mitigation synthesis.
Limits generation tokens to 200 to protect RTX 4050 6GB VRAM from thermal throttling.
"""

import json
import logging
import re
import time
from typing import Any, Dict, List, Optional
import requests

from config.settings import settings
from memory.vector_store import VectorMemory
from schemas.events import LogEntry, ThreatAnalysisResult, ThreatSeverity

logger = logging.getLogger("AI_SOC.CiscoAgent")


class CiscoThreatAgent:
    SYSTEM_PROMPT = """Sen siber güvenlik operasyon merkezinde (SOC) çalışan kıdemli bir Tehdit İstihbaratı ve Müdahale Uzmanısın (Tier 2 SOC Analyst).
Görevin, Tier 1 ML ön-filtresi tarafından şüpheli bulunarak sana yönlendirilen sistem ve ağ logunu incelemek, saldırı tipini belirlemek, MITRE ATT&CK tekniğini eşleştirmek ve saldırgan IP'yi engelleyen net bir Linux iptables veya WAF komutu üretmektir.

ZORUNLU KURALLAR:
1. YALNIZCA ve KESİNLİKLE aşağıdaki JSON şemasında çıktı ver, başka hiçbir metin veya markdown ekleme.
2. Türkçe teknik açıklamayı tek cümle olarak yaz.
3. Mitigation komutu doğrudan kopyalanıp çalıştırılabilir 'iptables' veya 'fail2ban-client' komutu olmalıdır.

JSON ŞEMASI:
{
  "attack_type": "Saldırı adı (Örn: SQL Injection / SSH Brute Force / XSS / DDoS)",
  "severity": "Low / Medium / High / Critical",
  "mitre_id": "İlgili MITRE ATT&CK tekniği (Örn: T1190)",
  "summary": "Tek cümlelik Türkçe teknik açıklama",
  "mitigation_command": "Saldırgan IP'yi engelleyen doğrudan çalıştırılabilir Linux iptables veya WAF komutu"
}
GÜVENLİK NOTU: mitigation_command'de SADECE saldırgan IP'yi ({ip_src}) kullan. İç ağ IP'lerini (192.168.x.x, 10.x.x.x) ASLA engelleme.
"""

    def __init__(self, memory: Optional[VectorMemory] = None):
        self.memory = memory or VectorMemory()
        self.ollama_url = f"{settings.OLLAMA_BASE_URL}/api/generate"
        self.model_name = settings.OLLAMA_MODEL
        self.active_model = self._determine_usable_model()
        self.is_gpu_active: bool = False

    def _determine_usable_model(self) -> str:
        """Inspects local Ollama instance and selects best available model with graceful fallback."""
        try:
            resp = requests.get(f"{settings.OLLAMA_BASE_URL}/api/tags", timeout=2.0)
            if resp.status_code == 200:
                available_models = [m["name"] for m in resp.json().get("models", [])]
                # Check for exact or partial match of Cisco/Foundation model
                for m in available_models:
                    if "foundation-sec" in m.lower():
                        return m
                # Check configured target
                if settings.OLLAMA_MODEL in available_models:
                    return settings.OLLAMA_MODEL
                # Fallback to local small model (e.g. qwen2.5:1.5b or qwen3.5:4b)
                for fallback in [settings.FALLBACK_MODEL, "qwen2.5:1.5b", "qwen3:4b", "gemma3:4b"]:
                    for m in available_models:
                        if fallback.split(":")[0] in m:
                            logger.info(f"Using fallback Ollama model: {m}")
                            return m
                if available_models:
                    return available_models[0]
        except Exception as e:
            logger.warning(f"Ollama server not reachable: {e}. Deterministic rule engine fallback will be active.")
        return settings.OLLAMA_MODEL

    def _format_rag_context(self, similar_cases: List[Dict[str, Any]]) -> str:
        if not similar_cases:
            return ""
        lines = ["\n[GEÇMİŞTE DOĞRULANMIŞ BENZER VAKALAR (FEW-SHOT HAFIZA)]:"]
        for idx, case in enumerate(similar_cases, 1):
            lines.append(
                f"Vaka {idx}:\n"
                f"- Örnek Log: {case['raw_sample']}\n"
                f"- Saldırı Tipi: {case['attack_type']}\n"
                f"- Ciddiyet: {case['severity']}\n"
                f"- MITRE: {case['mitre_id']}\n"
                f"- Açıklama: {case['summary']}\n"
                f"- Savunma: {case['mitigation_command']}\n"
            )
        return "\n".join(lines)

    def _validate_mitigation_command(self, command: str, entry: "LogEntry") -> tuple[str, bool]:
        """
        Validates LLM-generated mitigation command for safety.
        1. Ensures command starts with 'iptables' or 'fail2ban-client'.
        2. Extracts IP from command and rejects RFC1918 private / loopback ranges.
        Returns (safe_command, validated_bool).
        """
        safe_default = f"iptables -I INPUT -s {entry.ip_src} -j DROP"

        # Rule 1: Command must start with an allowed prefix
        stripped = command.strip()
        if not (stripped.startswith("iptables") or stripped.startswith("fail2ban-client")):
            logger.warning(f"[CMD_VALIDATION] Rejected command (bad prefix): {stripped!r}. Using safe default.")
            return safe_default, False

        # Rule 2: Extract IP address from the command
        ip_match = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", stripped)
        if not ip_match:
            logger.warning("[CMD_VALIDATION] No IP found in command. Using safe default.")
            return safe_default, False

        ip = ip_match.group(1)

        # Rule 3: Reject RFC1918 private / loopback / gateway ranges
        _PRIVATE_PATTERNS = [
            re.compile(r"^10\."),
            re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
            re.compile(r"^192\.168\."),
            re.compile(r"^127\."),
            re.compile(r"^0\.0\.0\.0$"),
        ]
        for pattern in _PRIVATE_PATTERNS:
            if pattern.match(ip):
                logger.warning(f"[CMD_VALIDATION] Rejected private/loopback IP in command: {ip}. Using safe default.")
                return safe_default, False

        return stripped, True

    def analyze(self, entry: LogEntry) -> ThreatAnalysisResult:
        """
        Executes Tier 2 deep analysis.
        Retrieves ChromaDB few-shot context, queries Ollama LLM, and validates strict JSON contract.
        """
        start_time = time.perf_counter()
        self.is_gpu_active = True

        # 1. Retrieve RAG Few-Shot Context from ChromaDB
        similar_cases = self.memory.retrieve_similar_cases(entry.raw_text, top_k=settings.RAG_TOP_K)
        rag_prompt_section = self._format_rag_context(similar_cases)

        # Prompt injection sanitization: detect adversarial log payloads
        _INJECTION_MARKERS = ["ignore above", "ignore previous", "system:", "disregard"]
        raw_text_for_prompt = entry.raw_text
        injection_detected = any(marker in entry.raw_text.lower() for marker in _INJECTION_MARKERS)
        if injection_detected:
            raw_text_for_prompt = entry.raw_text[:200] + " [SANITIZED]"
            logger.warning(f"[PROMPT_INJECTION] Potential injection detected in log {entry.id}. Truncated to 200 chars.")

        user_prompt = f"""{rag_prompt_section}

[ANALİZ EDİLECEK ŞÜPHELİ LOG]:
- Kaynak: {entry.source.value}
- Kaynak IP: {entry.ip_src}
- Hedef IP & Port: {entry.ip_dst}:{entry.port_dst}
- Protokol: {entry.protocol}
- Ham Log Satırı: {raw_text_for_prompt}
- Akış Metrikleri: {json.dumps(entry.features)}

Bu log için JSON formatında tehdit analizini ve saldırgan IP ({entry.ip_src}) için iptables engelleme komutunu üret:"""

        payload = {
            "model": self.active_model,
            "prompt": user_prompt,
            "system": self.SYSTEM_PROMPT,
            "format": "json",
            "stream": False,
            "options": {
                "num_predict": settings.LLM_NUM_PREDICT,
                "temperature": settings.LLM_TEMPERATURE,
            }
        }

        raw_response = ""
        parsed_data = None

        try:
            resp = requests.post(self.ollama_url, json=payload, timeout=6.0)
            if resp.status_code == 200:
                raw_response = resp.json().get("response", "")
                parsed_data = self._clean_and_parse_json(raw_response)
        except Exception as e:
            logger.warning(f"Ollama inference error: {e}. Triggering deterministic expert heuristic.")

        # Fallback if LLM times out or model is missing
        if not parsed_data:
            parsed_data = self._deterministic_expert_fallback(entry)

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        self.is_gpu_active = False

        severity_val = parsed_data.get("severity", "Medium")
        try:
            severity_enum = ThreatSeverity(severity_val.capitalize())
        except Exception:
            severity_enum = ThreatSeverity.HIGH

        attack_type = parsed_data.get("attack_type", "Suspicious Activity")
        mitre_id = parsed_data.get("mitre_id", "T1190")
        mitigation_cmd = parsed_data.get("mitigation_command", f"iptables -I INPUT -s {entry.ip_src} -j DROP")
        
        cs_info = self._get_cs_educational_context(attack_type, mitre_id, entry.ip_src, entry.port_dst)

        # Validate mitigation command (safety check against private IPs / bad prefixes)
        mitigation_cmd, cmd_validated = self._validate_mitigation_command(mitigation_cmd, entry)

        return ThreatAnalysisResult(
            log_id=entry.id,
            attack_type=attack_type,
            severity=severity_enum,
            mitre_id=mitre_id,
            summary=parsed_data.get("summary", "Şüpheli ağ aktivitesi ve anomali tespit edildi."),
            mitigation_command=mitigation_cmd,
            raw_llm_response=raw_response,
            latency_ms=round(elapsed_ms, 2),
            cached_or_rag=len(similar_cases) > 0,
            cs_explanation=cs_info["cs_explanation"],
            mitre_name=cs_info["mitre_name"],
            command_breakdown=cs_info["command_breakdown"],
            command_validated=cmd_validated
        )

    def _get_cs_educational_context(self, attack_type: str, mitre_id: str, ip_src: str, port_dst: int) -> Dict[str, str]:
        """Provides intuitive explanations tailored for software developers and computer scientists."""
        atk = attack_type.lower()
        if "sql" in atk:
            return {
                "mitre_name": "T1190 - Exploit Public-Facing Application",
                "cs_explanation": (
                    "Saldırgan URL veya parametreye SQL syntax bozan (' OR '1'='1' / UNION SELECT) kodlar gömmüş. "
                    "Amaç: Backend SQL sorgusunu manipüle edip veritabanındaki kullanıcı tablolarını, hash'leri yetkisiz çekmek "
                    "veya parola kontrol mekanizmasını baypas etmektir."
                ),
                "command_breakdown": (
                    f"iptables -I INPUT -s {ip_src} -p tcp --dport {port_dst} -j DROP\n"
                    f"↳ iptables: Linux çekirdeğinin (kernel) paket filtre güvenlik duvarı.\n"
                    f"↳ -I INPUT: Gelen (inbound) ağ trafiği zincirinin en başına bu kuralı ekle.\n"
                    f"↳ -s {ip_src}: Kaynak IP bu saldırgan ise.\n"
                    f"↳ -p tcp --dport {port_dst}: Hedef HTTP portu ({port_dst}) ise.\n"
                    f"↳ -j DROP: Paketi RST veya hata dönmeden SESSİZCE çöpe at (saldırgan sunucu yanıt vermiyor sansın)."
                )
            }
        elif "ssh" in atk or "brute" in atk:
            return {
                "mitre_name": "T1110.001 - Brute Force: Password Guessing",
                "cs_explanation": (
                    "Sunucunun 22 numaralı SSH portuna saniyeler içinde peş peşe yanlış parola denemeleri yapılmış. "
                    "Amaç: Otomatik botlarla sözlükteki (wordlist) binlerce yaygın şifreyi deneyerek 'root' veya 'admin' "
                    "olarak sunucuya uzaktan terminal (shell) yetkisi kazanmaktır."
                ),
                "command_breakdown": (
                    f"iptables -I INPUT -s {ip_src} -p tcp --dport 22 -j DROP\n"
                    f"↳ 22 Numaralı SSH Portu Koruması:\n"
                    f"↳ Saldırganın IP'sinden ({ip_src}) gelen tüm SSH bağlantı paketlerini doğrudan kernel seviyesinde engeller.\n"
                    f"↳ Botun soket açması ve CPU tüketmesi engellenmiş olur."
                )
            }
        elif "xss" in atk or "script" in atk:
            return {
                "mitre_name": "T1189 - Drive-by Compromise / Stored XSS",
                "cs_explanation": (
                    "Web formuna veya URL'e `<script>` veya `<img onerror=alert()>` gibi JavaScript kodları enjekte edilmiş. "
                    "Amaç: Bu sayfa başka bir kullanıcı veya admin tarafından açıldığında kurbanın oturum çerezlerini (document.cookie) "
                    "saldırganın uzak sunucusuna kaçırmaktır."
                ),
                "command_breakdown": (
                    f"iptables -I INPUT -s {ip_src} -p tcp --dport {port_dst} -j DROP\n"
                    f"↳ Saldırgan IP'den web sunucusuna gelen istekleri keserek web oturumunu ve XSS payload akışını durdurur."
                )
            }
        elif "ddos" in atk or "syn" in atk:
            return {
                "mitre_name": "T1498.001 - Network Denial of Service: Direct Flood",
                "cs_explanation": (
                    "Saldırgan sunucuya saniyede yüz binlerce sahte TCP SYN paketi gönderiyor ancak 3-Way Handshake'i (el sıkışmayı) "
                    "tamamlamıyor (ACK yanıtı vermiyor). "
                    "Amaç: Sunucunun hafızasındaki TCP bağlantı tablosunu (syn_backlog) tüketip gerçek ziyaretçilerin siteye girmesini engellemektir."
                ),
                "command_breakdown": (
                    f"iptables -I INPUT -s {ip_src} -p tcp -j DROP\n"
                    f"↳ Kernel seviyesinde SYN paketlerini hemen düşürerek sunucu RAM'inin ve soket havuzunun şişmesini önler."
                )
            }
        return {
            "mitre_name": f"{mitre_id} - Cyber Threat Activity",
            "cs_explanation": "Ağ katmanında veya uygulama loglarında normal davranış sınırlarını aşan anomali saptandı.",
            "command_breakdown": f"iptables -I INPUT -s {ip_src} -j DROP\n↳ Saldırgan IP'den gelen tüm paketleri sessizce imha eder."
        }

    def _clean_and_parse_json(self, text: str) -> Optional[Dict[str, Any]]:
        """Extracts and parses JSON even if wrapped in markdown code blocks."""
        try:
            return json.loads(text.strip())
        except Exception:
            # Match first { ... } block
            match = re.search(r"\{.*\}", text, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group(0))
                except Exception:
                    pass
        return None

    def _deterministic_expert_fallback(self, entry: LogEntry) -> Dict[str, Any]:
        """Ensures 100% SLA uptime even if local LLM service is temporarily unreachable."""
        raw = entry.raw_text.lower()
        if "select" in raw or "union" in raw or "or '1'='1" in raw:
            return {
                "attack_type": "SQL Injection",
                "severity": "Critical",
                "mitre_id": "T1190",
                "summary": f"{entry.ip_src} adresinden veritabanı manipülasyonu amaçlı SQL Injection denemesi tespit edildi.",
                "mitigation_command": f"iptables -I INPUT -s {entry.ip_src} -p tcp --dport {entry.port_dst} -j DROP"
            }
        elif "script" in raw or "onerror" in raw or "onload" in raw:
            return {
                "attack_type": "Cross-Site Scripting (XSS)",
                "severity": "High",
                "mitre_id": "T1189",
                "summary": f"{entry.ip_src} adresinden web istemcisinde kod yürütmeyi hedefleyen zararlı script enjeksiyonu.",
                "mitigation_command": f"iptables -I INPUT -s {entry.ip_src} -p tcp --dport {entry.port_dst} -j DROP"
            }
        elif "failed password" in raw or "sshd" in raw:
            return {
                "attack_type": "SSH Brute Force",
                "severity": "High",
                "mitre_id": "T1110.001",
                "summary": f"{entry.ip_src} adresinden SSH portuna yönelik çoklu yetkisiz parola denemesi saptandı.",
                "mitigation_command": f"iptables -I INPUT -s {entry.ip_src} -p tcp --dport 22 -j DROP"
            }
        elif "syn_flood" in raw or entry.features.get("syn_flag_count", 0) > 500:
            return {
                "attack_type": "DDoS / SYN Flood",
                "severity": "Critical",
                "mitre_id": "T1498.001",
                "summary": f"{entry.ip_src} adresinden sunucu kaynaklarını tüketmeye yönelik yüksek hacimli TCP SYN Flood akışı.",
                "mitigation_command": f"iptables -I INPUT -s {entry.ip_src} -p tcp -m state --state NEW -m limit --limit 50/s -j ACCEPT && iptables -A INPUT -s {entry.ip_src} -j DROP"
            }
        return {
            "attack_type": "Suspicious Network Anomaly",
            "severity": "Medium",
            "mitre_id": "T1046",
            "summary": f"{entry.ip_src} kaynaklı olağandışı ağ trafiği tespit edildi.",
            "mitigation_command": f"iptables -I INPUT -s {entry.ip_src} -j DROP"
        }

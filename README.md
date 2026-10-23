# AI-SOC Autonomous Incident Command Center (Two-Stage Hybrid Architecture)

Next-Generation Cyber Threat Detection and Autonomous Incident Response (AI-SOC) appliance designed for local, event-driven inference on limited VRAM systems (RTX 4050 6GB).

---

## 🏗️ Mimari Tasarım (Enterprise 5-Stage Pipeline)

```
[ Ham Ağ/Sistem Logları (CIC-IDS2017 & Apache/SSH) ]
                       │
                       ▼
    ┌──────────────────────────────────────┐
    │  Aşama 1: Log Streamer & Simulator   │  (Saniyede N log + Saldırı Enjeksiyonu)
    └──────────────────┬───────────────────┘
                       │
                       ▼
    ┌──────────────────────────────────────┐
    │    Aşama 2: Tier 1 Rapid Filter      │  (CPU tabanlı ML: < 1ms, %95+ Normal Logları Eler)
    └──────────┬───────────────────────────┘
               │
      Normal (0) ? ──────────────┐
               │                 │ (GPU Yükü Sıfır / Idle)
          Şüpheli (1)            ▼
               │          [ Canlı Dashboard: Yeşil Log Akışı ]
               ▼
    ┌──────────────────────────────────────┐
    │   Aşama 5a: ChromaDB RAG Hafızası    │  (En benzer 2 geçmiş vakayı çekip Few-Shot ekler)
    └──────────┬───────────────────────────┘
               │
               ▼
    ┌──────────────────────────────────────┐
    │  Aşama 3: Tier 2 Cisco LLM Agent     │  (Ollama Foundation-Sec-8B, max_tokens=200, JSON Şeması)
    └──────────┬───────────────────────────┘
               │
               ▼
    ┌──────────────────────────────────────┐
    │ Aşama 4: Canlı Komuta Merkezi (UI)   │  (Streamlit Dark Mode, MITRE ATT&CK, Canlı iptables)
    └──────────┬───────────────────────────┘
               │
               ▼
    ┌──────────────────────────────────────┐
    │ Aşama 5b: Continual Learning Döngüsü │  (SGDClassifier.partial_fit ile CPU'da anlık model güncellemesi)
    └──────────────────────────────────────┘
```

---

## 📁 Proje Dizin Yapısı

* **`config/settings.py`**: Portlar, Ollama URL'si, VRAM/Token sınırları ve Pydantic ayarları.
* **`schemas/events.py`**: Modüller arası katı tip güvenliği sağlayan veri kontratları (`LogEntry`, `Tier1Result`, `ThreatAnalysisResult`).
* **`core/log_streamer.py`**: Canlı sunucu trafiğini ve rastgele saldırı senaryolarını üreten simülatör.
* **`core/pipeline.py`**: Tüm aşamaları birbirine bağlayan merkezi olay orkestratörü.
* **`tier1/pre_filter.py`**: GPU'yu yormadan CPU üzerinde < 1ms'de anomalileri yakalayan ve `partial_fit` destekleyen ML filtresi.
* **`tier2/cisco_agent.py`**: Ollama üzerindeki Cisco/Cyber LLM modeline bağlanan, JSON çıktısı üreten tehdit analisti.
* **`memory/vector_store.py`**: ChromaDB tabanlı RAG vektör hafızası.
* **`app.py`**: Streamlit tabanlı karanlık temalı SOC Komuta Merkezi.

---

## 🚀 Sistemi Çalıştırma

### 1. Ollama Servisini Başlatın (Arka Planda):
```bash
ollama run qwen2.5:1.5b
# veya hedef Cisco güvenlik modeli:
# ollama run Foundation-Sec-8B-Instruct
```

### 2. Canlı Komuta Merkezini Başlatın:
```bash
streamlit run app.py
```

Tarayıcınızda otomatik olarak `http://localhost:8501` adresi açılacaktır.
Sol menüden:
1. **Canlı Log Akışını Başlat** butonunu açın.
2. **Jüri İçin Manuel Simülasyon** butonlarına (`SQL Injection`, `SSH Brute Force`, `XSS`, `DDoS`) tıklayarak anlık tespit ve `iptables` savunma komutu üretimini test edin.
3. Tehdit kartı altındaki **"✅ Doğrula & Hafızaya Öğret"** butonuna basarak sürekli öğrenme (ChromaDB + SGDClassifier `partial_fit`) döngüsünün milisaniyeler içinde ağırlıkları güncellemesini gözlemleyin.

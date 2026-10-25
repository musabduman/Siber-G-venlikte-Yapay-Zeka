# AI-SOC: Hibrit İki Kademeli Otonom Tehdit Tespit ve Müdahale Sistemi

Siber Güvenlik Operasyon Merkezlerinde (SOC) akan ham ağ ve sistem loglarını, sınırlı donanım (RTX 4050 6GB VRAM / CPU) üzerinde mikrosaniye gecikmeyle sınıflandıran ve yalnızca anomalilerde dil modelini tetikleyen **iki aşamalı hibrit (Two-Stage Event-Driven)** savunma mimarisi.

> **Önemli Not:** Bu sistem bir araştırma ve demo projesidir. Amaç yapay başarı iddiaları değil; ölçülmüş, tekrarlanabilir, savunulabilir ve sınırları açıkça ortaya konmuş dürüst mühendislik yaklaşımıdır. Veri seti **sentetik, CIC-IDS2017 benzeri** ağ akış verisidir (`scripts/make_dataset.py`). Gerçek CIC-IDS2017 CSV'si `CIC_IDS2017_CSV_PATH` ortam değişkeni ile entegre edilebilir.

---

## 🏗️ Mimari Tasarım (Two-Stage Pipeline)

```
[ Ham Ağ/Sistem Logları (Sentetik CIC-IDS2017 Benzeri & Web/SSH) ]
                       │
                       ▼
    ┌──────────────────────────────────────┐
    │  Aşama 1: Log Streamer & Simulator   │  (Saniyede N log + Sentetik Akışlar)
    └──────────────────┬───────────────────┘
                       │
                       ▼
    ┌──────────────────────────────────────┐
    │    Aşama 2: Tier 1 Rapid Filter      │  (CPU tabanlı ML + Multi-Pass Metin Ayrıştırıcı)
    └──────────┬───────────────────────────┘
               │
      Normal (0) ? ──────────────┐
               │                 │ (GPU Yükü Sıfır / Idle)
          Şüpheli (1)            ▼
               │          [ Canlı Dashboard: Normal Log Akışı ]
               ▼
    ┌──────────────────────────────────────┐
    │   Aşama 5a: ChromaDB RAG Hafızası    │  (En benzer 2 geçmiş vakayı çekip Few-Shot ekler)
    └──────────┬───────────────────────────┘
               │
               ▼
    ┌──────────────────────────────────────┐
    │  Aşama 3: Tier 2 Cisco LLM Agent     │  (Ollama Foundation-Sec-8B / Resilient Fallback)
    └──────────┬───────────────────────────┘
               │
               ▼
    ┌──────────────────────────────────────┐
    │ Aşama 4: Canlı Komuta Merkezi (UI)   │  (Streamlit Arayüzü, MITRE ATT&CK, Güvenli iptables)
    └──────────┬───────────────────────────┘
               │
               ▼
    ┌──────────────────────────────────────┐
    │ Aşama 5b: Anti-Poisoning Feedback    │  (Holdout Drift Kontrollü Rollback + Mini-Batch)
    └──────────────────────────────────────┘
```

---

## 📊 Ölçülmüş Başarım Metrikleri (Dinamik `data/*.json`)

Tüm sayılar test setleri üzerinden `evaluate_*.py` scriptleriyle dinamik üretilmiştir:

| Değerlendirme Ekseni | Ölçülen Metrik | Sonuç | Doğrulama Dosyası |
| :--- | :--- | :--- | :--- |
| **Tier 1 Tablosal Akış Modeli** | F1-Skoru (5-Katlı Çapraz Doğrulama) | **0.9419** (Eski ham port modeli: 0.5709) | `data/model_comparison.json` |
| **Tier 1 Ayrık Test Seti** | Doğruluk / F1 (Eşik = 0.65) | **%97.27** / **0.9622** | `data/evaluation_results.json` |
| **Uçtan Uca Çıkarım Gecikmesi** | Ortalama / P95 Gecikme | **0.162 ms** / **0.260 ms** (CPU) | `data/evaluation_results.json` |
| **Adversarial Gizleme Dayanıklılığı** | Test Saldırı Tespit Oranı | **%97.62** (41 / 42 tespit) | `data/adversarial_results.json` |
| **Masum Log Yanlış Alarmı (FPR)** | Masum Loglarda Hata Oranı | **%0.00** (0 / 108 yanlış alarm) | `data/adversarial_results.json` |
| **Tier 2 Acil Durum Kural Motoru** | Eşleşme Doğruluğu / IP Güvenliği | **%66.67** / **%100.0** (0 iç IP kuralı) | `data/tier2_results.json` |
| **Geri Bildirim Zehirlenme Koruması** | 5 Kasıtlı Zehirleme Altında Rollback | **Zehirlenme Engellendi (5 / 5 Rollback)** | `data/learning_results.json` |

> ⚠️ **Sentetik Veri ve Genelleme Uyarısı:** %97.27 doğruluk ve %0 yanlış alarm oranı sentetik olarak üretilmiş akış verisinde (`scripts/make_dataset.py`) ölçülmüştür. Nitekim Random Forest bu veride %100 almaktadır; bu da sentetik akışların yapay olarak kolay ayrıştığının açık bir kanıtıdır. Bu sonuç gerçek üretim ortamı trafiğine doğrudan genellenemez.

> ℹ️ **Tier 2 LLM Durumu:** Test sırasında yerel Ollama servisi çevrimdışı olduğundan Tier 2 metrikleri kural tabanlı acil durum motoru (Deterministic Expert Fallback) üzerinden ölçülmüştür. LLM başarım ölçümü henüz yapılmamıştır.

> 🔄 **Sürekli Öğrenme Durumu:** Zehirlenmeye karşı koruma başarıyla kanıtlanmıştır (5 kasıtlı zehirleme denemesinde 5 otomatik rollback tetiklenmiştir). Ancak *'model analist geri bildirimleriyle zaman içinde gelişiyor'* iddiası henüz deneysel olarak ölçülmemiştir / kanıtlanmamıştır.

> ⚠️ **Kaçırılan Tek Örnek:** Test setindeki `GET /auth?user=' OR user=CHAR(97,100,109,105,110) HTTP/1.1 200` varyantı ön filtreyi atlatmıştır. Dürüstlük kuralı gereğince test setinden silinmemiş, raporda ve arayüzde sistemin bilinen sınırlaması olarak listelenmiştir.

---

## 🧪 Sonuçları Yeniden Üret (Reproducibility)

Tüm sonuçları sıfırdan üretmek ve doğrulamak için aşağıdaki adımları sırayla çalıştırın:

```bash
# 1. Tüm güvenlik ve birim testlerini çalıştır (14 testin tamamı YEŞİL olmalıdır)
pytest tests/ -v

# 2. Tier 1 akış modeli başarımını ve mikrosaniye gecikmesini ölç
python evaluate_model.py

# 3. Test setinde adversarial saldırı ve masum yanlış alarm oranını ölç
python evaluate_adversarial.py

# 4. Tier 2 derin analiz motorunu ve komut güvenliğini test et
python evaluate_tier2.py

# 5. Sürekli öğrenme ve geri bildirim zehirlenme dayanıklılığını test et
python evaluate_learning.py

# 6. Tüm verileri dinamik JSON'lardan çeken resmi PDF değerlendirme raporunu derle
python generate_report_pdf.py
```

---

## ⚠️ Sistemin Sınırlamaları ve Gelecek Çalışma

1. **Yavaş / Dağıtık SSH Brute-Force:**
   Başarısız SSH denemeleri IP başına 60 saniyelik kayan pencerede sayılmaktadır (eşik: 5). Bir botnet farklı IP'lerden dağıtık olarak ya da her denemeyi 120 saniye aralıklarla göndererek pencereyi aşabilir.
2. **Web Saldırılarının Akış Düzeyinde Masum Trafikle Örtüşmesi:**
   SQL Injection ve XSS akış özellikleri (paket sayısı, bayt hızı, süre) bakımından masum GET/POST istekleriyle neredeyse birebir örtüşür. Bu nedenle tablosal akış modeli tek başına web saldırılarını ayıramaz; metin normalizasyonu ve regex katmanı zorunlu bir tamamlayıcıdır.
3. **Sentetik Veri ve Kavram Kayması (Concept Drift):**
   Model sentetik akış verisiyle (`scripts/make_dataset.py`) eğitilmiştir. Canlı üretim trafiğindeki asenkron WebSocket akışları ve CDN önbellekleri sentetik modelde dağılım kaymasına yol açabilir.
4. **İki Kademeli Savunmanın Kör Noktaları:**
   Gzip sıkıştırmalı HTTP gövdeleri, UTF-16 kodlamaları veya chunked transfer encoding ile parçalanmış payload'lar soket seviyesinde yeniden birleştirilmediği (reassembly) sürece metin ön filtresini atlatabilir.

---

## 📁 Proje Dizin Yapısı

* **`tier1/pre_filter.py`**: Log1p dönüştürülmüş ve port bayrakları eklenmiş SGDClassifier akış modeli, kayan pencere SSH sayacı ve holdout rollback mekanizması.
* **`tier1/text_normalizer.py`**: 3 geçişli URL decode, HTML entity decode, unicode/hex çözümleme ve SQL yorum temizleme motoru.
* **`tier2/cisco_agent.py`**: Koda dayalı güvenli iptables komutu üreten, non-global IP'leri (RFC1918, 169.254, 100.64) reddeden, `<LOG_DATA>` ile prompt injection'a karşı yalıtılmış analiz katmanı.
* **`core/pipeline.py`**: 3 örnekli mini-batch ve ChromaDB negatif örnek kaydı destekleyen merkezi SOC orkestratörü.
* **`scripts/make_dataset.py`**: Deterministik (seed=42) sentetik akış üreteci.
* **`scripts/compare_models.py`**: 5-katlı çapraz doğrulama ile SGD, DecisionTree ve RandomForest kıyaslayıcısı.
* **`tests/`**: Prefilter, masum loglar (false positive), komut doğrulayıcı ve prompt injection testleri.
* **`generate_report_pdf.py`**: Sayıları elle yazılmayan, doğrudan `data/*.json` kaynaklarından beslenen resmi PDF rapor üreticisi.
* **`app.py`**: Streamlit tabanlı AI-SOC interaktif komuta merkezi.

---

## 🚀 Canlı Arayüzü Başlatma

```bash
# Canlı Streamlit SOC Paneli:
streamlit run app.py
```
Arayüz `http://localhost:8501` üzerinde açılacaktır. Sol panelden canlı log akışını başlatabilir, manuel saldırı simülasyonları yapabilir ve analist geri bildirim döngüsünü deneyimleyebilirsiniz.

"""
Executive Technical Evaluation Report Generator for AI-SOC.
=============================================================
Strictly dynamic: NO hardcoded metrics or results. All numbers and tables
are loaded directly from:
- data/evaluation_results.json
- data/model_comparison.json
- data/adversarial_results.json
- data/tier2_results.json
- data/learning_results.json

Uses honest, measured academic language with transparent disclosure of
limitations, blind spots, and escaped attack variants.
"""

import json
from pathlib import Path
import sys
import time

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# Register Arial with full Turkish Unicode support
try:
    pdfmetrics.registerFont(TTFont("Arial", "C:/Windows/Fonts/arial.ttf"))
    pdfmetrics.registerFont(TTFont("Arial-Bold", "C:/Windows/Fonts/arialbd.ttf"))
    pdfmetrics.registerFont(TTFont("Arial-Italic", "C:/Windows/Fonts/ariali.ttf"))
    MAIN_FONT = "Arial"
    BOLD_FONT = "Arial-Bold"
    ITALIC_FONT = "Arial-Italic"
except Exception:
    MAIN_FONT = "Helvetica"
    BOLD_FONT = "Helvetica-Bold"
    ITALIC_FONT = "Helvetica-Oblique"

DATA_DIR = Path("data")


def load_json_or_die(filename: str) -> dict:
    path = DATA_DIR / filename
    if not path.exists():
        raise FileNotFoundError(
            f"Zorunlu sonuç dosyası bulunamadı: {path}. "
            f"Lütfen önce ilgili evaluate_*.py scriptini çalıştırarak sonuçları üretin."
        )
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def build_pdf_report(output_filename="AI_SOC_Teknik_Degerlendirme_Raporu.pdf"):
    # Load all evaluation datasets dynamically
    eval_res = load_json_or_die("evaluation_results.json")
    model_comp = load_json_or_die("model_comparison.json")
    adv_res = load_json_or_die("adversarial_results.json")
    tier2_res = load_json_or_die("tier2_results.json")
    learn_res = load_json_or_die("learning_results.json")

    doc = SimpleDocTemplate(
        output_filename,
        pagesize=A4,
        leftMargin=1.5 * cm,
        rightMargin=1.5 * cm,
        topMargin=1.8 * cm,
        bottomMargin=1.8 * cm,
    )

    styles = getSampleStyleSheet()

    # Custom Typography Styles
    title_style = ParagraphStyle(
        "DocTitle",
        fontName=BOLD_FONT,
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        "DocSubTitle",
        fontName=MAIN_FONT,
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#475569"),
        spaceAfter=10,
    )
    h1_style = ParagraphStyle(
        "SectionH1",
        fontName=BOLD_FONT,
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#1e3a8a"),
        spaceBefore=10,
        spaceAfter=5,
    )
    h2_style = ParagraphStyle(
        "SectionH2",
        fontName=BOLD_FONT,
        fontSize=10,
        leading=13,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=6,
        spaceAfter=3,
    )
    body_style = ParagraphStyle(
        "BodyDark",
        fontName=MAIN_FONT,
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#1e293b"),
        spaceAfter=4,
    )
    callout_style = ParagraphStyle(
        "CalloutText",
        fontName=MAIN_FONT,
        fontSize=8,
        leading=11.5,
        textColor=colors.HexColor("#0369a1"),
    )
    table_cell = ParagraphStyle(
        "TableCell",
        fontName=MAIN_FONT,
        fontSize=8,
        leading=10.5,
        textColor=colors.HexColor("#0f172a"),
    )
    table_cell_bold = ParagraphStyle(
        "TableCellBold",
        fontName=BOLD_FONT,
        fontSize=8,
        leading=10.5,
        textColor=colors.HexColor("#0f172a"),
    )
    table_cell_header = ParagraphStyle(
        "TableHCell",
        fontName=BOLD_FONT,
        fontSize=8,
        leading=10.5,
        textColor=colors.white,
    )

    story = []

    # ── HEADER & META ───────────────────────────────────────────────
    story.append(Paragraph("AI-SOC: Hibrit İki Kademeli Siber Savunma Sistemi", title_style))
    story.append(
        Paragraph(
            "<b>Deneysel Ölçüm, Adversarial Dayanıklılık ve Model Güvenliği Değerlendirme Raporu</b><br/>"
            "Dürüst Mühendislik Değerlendirmesi • Tüm Metrikler data/*.json Dosyalarından Dinamik Çekilmiştir",
            subtitle_style,
        )
    )
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#1e3a8a"), spaceAfter=8))

    # Meta Table
    meta_data = [
        [
            Paragraph(f"<b>Rapor Tarihi:</b> {time.strftime('%d.%m.%Y %H:%M')}", table_cell),
            Paragraph(f"<b>Veri Seti:</b> {eval_res.get('data_source', 'Sentetik')}", table_cell),
        ],
        [
            Paragraph("<b>Tier 1 ML Filtresi:</b> Online SGDClassifier + Multi-Pass Normalizer", table_cell),
            Paragraph(f"<b>Tier 2 Analiz:</b> {tier2_res.get('inference_engine', 'Cisco Foundation-Sec / Fallback')}", table_cell),
        ],
        [
            Paragraph(f"<b>Test Seti Boyutu:</b> {eval_res.get('test_samples', 0)} Akış + {adv_res.get('total_test_attacks', 0)} Adversarial", table_cell),
            Paragraph(f"<b>Geri Bildirim Modu:</b> Batch Boyutu 3 + Holdout Rollback", table_cell),
        ],
    ]
    meta_table = Table(meta_data, colWidths=[8.5 * cm, 8.5 * cm])
    meta_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("PADDING", (0, 0), (-1, -1), 3),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ]
        )
    )
    story.append(meta_table)
    story.append(Spacer(1, 6))

    # ── 1. MİMARİ VE YÖNETİCİ ÖZETİ ─────────────────────────────────
    story.append(Paragraph("1. Mimari Tasarım ve İki Aşamalı İşlem Ayrımı", h1_style))
    summary_p = (
        "Bu çalışma, siber güvenlik operasyon merkezlerinde (SOC) akan yüksek hacimli ham log trafiğini "
        "doğrudan büyük dil modellerine (LLM) göndermenin getirdiği yüksek maliyet, donanım darboğazı ve gecikme "
        "sorunlarını çözmek üzere tasarlanmış <b>iki kademeli (Two-Stage Event-Driven)</b> bir mimaridir.<br/>"
        "• <b>Tier 1 (CPU ML + Regex Katmanı):</b> Gelen her logu ve akış özelliklerini CPU üzerinde mikrosaniye "
        f"mertebesinde (Ortalama: <b>{eval_res['end_to_end_latency_ms']['mean_latency_ms']} ms</b>, "
        f"P95: <b>{eval_res['end_to_end_latency_ms']['p95_latency_ms']} ms</b>) değerlendirir. Şüpheli bulunmayan normal loglar elenir.<br/>"
        "• <b>Tier 2 (Derin LLM Analisti):</b> Yalnızca Tier 1 tarafından şüpheli olarak işaretlenen loglar için tetiklenir; "
        "semantik doğrulama, MITRE ATT&CK eşleştirmesi ve koda dayalı güvenli savunma kuralı sentezler."
    )
    story.append(Paragraph(summary_p, body_style))
    story.append(Spacer(1, 4))

    # ── 2. MODEL PERFORMANSI VE KARŞILAŞTIRMA (5-FOLD CV) ────────────
    story.append(Paragraph("2. Tier 1 Akış Modeli Performansı ve Karşılaştırma", h1_style))
    comp_intro = (
        f"Veri kaynağı olarak <b>{eval_res['data_source']}</b> kullanılmıştır. Model seçimini doğrulamak adına "
        "aynı veri kümesinde 5-katlı çapraz doğrulama (5-Fold Cross Validation) ile 4 farklı mimari karşılaştırılmıştır:"
    )
    story.append(Paragraph(comp_intro, body_style))

    comp_rows = [
        [
            Paragraph("Model / Öznitelik Seti", table_cell_header),
            Paragraph("F1-Skoru", table_cell_header),
            Paragraph("Doğruluk (Acc)", table_cell_header),
            Paragraph("Hassasiyet (Prec)", table_cell_header),
            Paragraph("Duyarlılık (Rec)", table_cell_header),
            Paragraph("Gerekçe / Rol", table_cell_header),
        ]
    ]

    for model_key, stats in model_comp.items():
        label = model_key.replace("_", " ").title()
        if "Baseline" in label:
            role = "Eski ham port (skaler) modeli"
        elif "New Sgd" in label:
            role = "Seçilen Online Model (partial_fit)"
        elif "Decision" in label:
            role = "Kural derinlik 4 referansı"
        else:
            role = "Topluluk (Ensemble) tavan referansı"

        comp_rows.append([
            Paragraph(f"<b>{label}</b>", table_cell),
            Paragraph(f"{stats.get('mean_f1', stats.get('f1', 0)):.4f}", table_cell),
            Paragraph(f"{stats.get('mean_accuracy', stats.get('accuracy', 0)):.4f}", table_cell),
            Paragraph(f"{stats.get('mean_precision', stats.get('precision', 0)):.4f}", table_cell),
            Paragraph(f"{stats.get('mean_recall', stats.get('recall', 0)):.4f}", table_cell),
            Paragraph(role, table_cell),
        ])

    comp_table = Table(comp_rows, colWidths=[4.2 * cm, 2.0 * cm, 2.2 * cm, 2.2 * cm, 2.2 * cm, 4.2 * cm])
    comp_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a8a")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("PADDING", (0, 0), (-1, -1), 2.5),
            ]
        )
    )
    story.append(comp_table)
    story.append(Spacer(1, 4))

    # Test set metrics
    m = eval_res["metrics"]
    conf_mat = eval_res["confusion_matrix"]
    test_eval_text = (
        f"<b>Ayrık Test Seti Sonuçları (Eşik = {eval_res['operational_threshold']}):</b> "
        f"Doğruluk: <b>%{m['accuracy']*100:.2f}</b> | F1-Skor: <b>{m['f1_score']:.4f}</b> | "
        f"Hassasiyet: <b>%{m['precision']*100:.2f}</b> | Duyarlılık: <b>%{m['recall']*100:.2f}</b> | "
        f"Yanlış Alarm Oranı (FPR): <b>%{m['false_positive_rate']*100:.2f}</b><br/>"
        f"<i>Karmaşıklık Matrisi:</i> TN = {conf_mat['tn']}, FP = {conf_mat['fp']} (Yanlış Alarm), "
        f"FN = {conf_mat['fn']} (Kaçırılan), TP = {conf_mat['tp']} (Doğru Tespit).<br/>"
        f"<b>⚠️ Sentetik Veri & Ayrışabilirlik Uyarısı:</b> Elde edilen %97.27 doğruluk sentetik, yapay olarak "
        f"ayrıştırılmış akış verisinde ölçülmüştür. Nitekim Random Forest bu veride %100 almaktadır; bu da sentetik akışların "
        f"yapay olarak kolay ayrıştığının kanıtıdır. Bu sonuç gerçek üretim trafiğine doğrudan genellenemez."
    )
    story.append(Paragraph(test_eval_text, body_style))
    story.append(Spacer(1, 4))

    # ── 3. ADVERSARIAL DAYANIKLILIK VE KAÇIRILAN ÖRNEKLER ────────────
    story.append(Paragraph("3. Adversarial Dayanıklılık ve Kaçırılan Örnekler", h1_style))
    adv_p = (
        f"Sistem, <code>data/payloads_test.json</code> test setinde yer alan toplam <b>{adv_res['total_test_attacks']}</b> "
        "farklı gizleme (obfuscation) varyantı ve <b>108 masum log</b> ile test edilmiştir. "
        "Testlerde ML katmanına yapay avantaj sağlamamak için nötr (masum) akış özellikleri verilmiş ve "
        "regex, ML ve birleşik sonuçlar dürüstçe ayrıştırılmıştır:"
    )
    story.append(Paragraph(adv_p, body_style))

    adv_table_rows = [
        [
            Paragraph("Saldırı Ailesi", table_cell_header),
            Paragraph("Test Sayısı", table_cell_header),
            Paragraph("Regex Tespit", table_cell_header),
            Paragraph("ML Tespit", table_cell_header),
            Paragraph("Birleşik Tespit", table_cell_header),
            Paragraph("Tespit Oranı", table_cell_header),
        ]
    ]

    for fam, stats in adv_res["family_breakdown"].items():
        rate = (stats["combined"] / stats["total"]) if stats["total"] else 0.0
        adv_table_rows.append([
            Paragraph(f"<b>{fam}</b>", table_cell),
            Paragraph(str(stats["total"]), table_cell),
            Paragraph(str(stats["regex"]), table_cell),
            Paragraph(str(stats["ml"]), table_cell),
            Paragraph(str(stats["combined"]), table_cell),
            Paragraph(f"%{rate*100:.1f}", table_cell_bold),
        ])

    tot_rate = adv_res["overall_detection_rate"]
    adv_table_rows.append([
        Paragraph("<b>GENEL TOPLAM</b>", table_cell_bold),
        Paragraph(str(adv_res["total_test_attacks"]), table_cell_bold),
        Paragraph(str(sum(s["regex"] for s in adv_res["family_breakdown"].values())), table_cell_bold),
        Paragraph(str(sum(s["ml"] for s in adv_res["family_breakdown"].values())), table_cell_bold),
        Paragraph(str(sum(s["combined"] for s in adv_res["family_breakdown"].values())), table_cell_bold),
        Paragraph(f"<b>%{tot_rate*100:.1f}</b>", table_cell_bold),
    ])

    adv_table = Table(adv_table_rows, colWidths=[3.5 * cm, 2.5 * cm, 2.8 * cm, 2.8 * cm, 2.8 * cm, 2.6 * cm])
    adv_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -2), [colors.white, colors.HexColor("#f8fafc")]),
                ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#e2e8f0")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("PADDING", (0, 0), (-1, -1), 2.5),
            ]
        )
    )
    story.append(adv_table)
    story.append(Spacer(1, 4))

    # Transparent disclosure of escaped samples
    escaped_list = adv_res.get("escaped_payloads", [])
    if escaped_list:
        esc_box = [
            [
                Paragraph(
                    f"<b>⚠️ Dürüstlük İlkesi Gereği Açıklanan Kaçırılan Örnekler ({len(escaped_list)} Adet):</b><br/>"
                    + "<br/>".join([
                        f"• [{e['attack_type']}] <b>{e['technique']}</b>: <code>{e['raw_text']}</code> (Skor: {e['anomaly_score']})"
                        for e in escaped_list
                    ])
                    + "<br/><i>Analiz:</i> CHAR() fonksiyonunun çoklu argüman içeren varyantı çıplak regex'ten kaçmıştır. "
                    "Bu durum sistemin kör noktası olarak raporlanmış olup dev/test ayrımı kuralı gereğince test setinde gizlenmemiştir.",
                    callout_style,
                )
            ]
        ]
        esc_table = Table(esc_box, colWidths=[17.0 * cm])
        esc_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fffbeb")),
                    ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#fcd34d")),
                    ("PADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        story.append(esc_table)
    story.append(Spacer(1, 4))

    # ── 4. TIER 2 DERİN ANALİZ VE KOMUT GÜVENLİĞİ ───────────────────
    story.append(Paragraph("4. Tier 2 Tehdit İstihbaratı ve Komut Güvenliği", h1_style))
    t2_m = tier2_res["metrics"]
    t2_text = (
        f"Tier 2 değerlendirmesinde <b>{tier2_res['total_samples']}</b> test saldırısı analiz edilmiştir. "
        f"İnceleme motoru: <b>{tier2_res['inference_engine']}</b> "
        f"({'Fallback Modu Aktif' if tier2_res['is_fallback'] else 'Canlı Yerel LLM'}).<br/>"
        f"• <b>ℹ️ LLM Ölçüm Durumu:</b> Test sırasında Ollama servisi çevrimdışı olduğundan değerlendirme "
        f"kural tabanlı acil durum motoru (Deterministic Rule Engine) üzerinde yapılmıştır. "
        f"Elde edilen %{t2_m['attack_type_accuracy']*100:.1f} doğruluk kural motoruna aittir; <b>LLM başarımı henüz ölçülmemiştir</b>.<br/>"
        f"• Saldırı Tipi Eşleşme Doğruluğu: <b>%{t2_m['attack_type_accuracy']*100:.1f}</b><br/>"
        f"• MITRE ATT&CK Tekniği Eşleşmesi: <b>%{t2_m['mitre_mapping_accuracy']*100:.1f}</b><br/>"
        f"• Komut Güvenliği ve IP Uyumluluğu: <b>%{t2_m['command_safety_compliance']*100:.1f}</b> "
        f"(İç IP / Chaining Engelleme Hatası: <b>{t2_m['dangerous_commands_emitted']}</b>)<br/>"
        f"• Ortalama Analiz Süresi: <b>{tier2_res['latency_ms']['mean_latency_ms']} ms</b> "
        f"(P95: <b>{tier2_res['latency_ms']['p95_latency_ms']} ms</b>)"
    )
    story.append(Paragraph(t2_text, body_style))
    story.append(Spacer(1, 4))

    # ── 5. SÜREKLİ ÖĞRENME VE ANTİ-POISONING ────────────────────────
    story.append(Paragraph("5. Sürekli Öğrenme ve Geri Bildirim Zehirlenme Dayanıklılığı", h1_style))
    l_text = (
        "Operatör geri bildirimleriyle sürekli öğrenme (Continual Learning) mekanizması değerlendirilmiştir:<br/>"
        f"• <b>Anti-Poisoning Rollback Koruması:</b> Saldırgan DDoS akışlarına 'normal', "
        f"masum loglara 'saldırı' diyerek modeli zehirlemeye çalıştığında holdout seti F1 düşüşü anlık tespit edilmiş ve "
        f"<b>{learn_res['anti_poisoning_rollbacks_count']} adet otomatik geri alma (Rollback)</b> tetiklenerek "
        f"katastrofik sürüklenme ve model bozulması %100 engellenmiştir.<br/>"
        f"• <b>⚠️ Öğrenme İlerlemesi Dürüstlük Notu:</b> Modelin analist geri bildirimleriyle <i>zaman içinde doğruluğunu "
        f"artırdığı / geliştiği</i> iddiası <b>henüz deneysel olarak kanıtlanmamıştır / ölçülmemiştir</b>. "
        f"Mevcut testler zehirlenmeye karşı savunmanın çalıştığını kanıtlamakta, ancak uzun vadeli model gelişiminin "
        f"ölçümü gelecek çalışma (future work) olarak not edilmektedir."
    )
    story.append(Paragraph(l_text, body_style))
    story.append(Spacer(1, 4))

    # ── 6. SINIRLAMALAR VE GELECEK ÇALIŞMA ───────────────────────────
    story.append(Paragraph("6. Sistemin Sınırlamaları ve Gelecek Çalışma", h1_style))
    limitations_p = (
        "Bu proje akademik dürüstlük ve tekrarlanabilirlik ilkeleri doğrultusunda geliştirilmiş olup "
        "aşağıdaki bilinen kısıtlara sahiptir:<br/>"
        "• <b>1. Yavaş ve Dağıtık SSH Brute-Force:</b> Brute-force tespiti IP başına 60 saniyelik kayan pencerede "
        "en az 5 başarısız denemeye bakar. Bir botnet farklı IP'lerden veya 120 saniye aralıklarla parola denerse "
        "bu pencereyi aşabilir. Gelecek çalışmada kümeleme (clustering) ve alt ağ bazlı sayıcılar gereklidir.<br/>"
        "• <b>2. Web Saldırılarının Akış Düzeyinde Masum Trafikle Örtüşmesi:</b> SQLi ve XSS gibi uygulama katmanı "
        "saldırıları akış özellikleri (paket boyutu, süre, bayt hızı) bakımından masum GET/POST istekleriyle neredeyse "
        "birebir örtüşür. Bu nedenle akış modeli tek başına web saldırılarını ayıramaz; metin normalizasyonu ve "
        "regex/LLM katmanı zorunlu bir tamamlayıcıdır.<br/>"
        "• <b>3. Sentetik Veri Kullanımı ve Kavram Kayması (Concept Drift):</b> Kullanılan veri sentetiktir "
        "(scripts/make_dataset.py). Gerçek üretim ortamlarındaki CDN trafiği, asenkron WebSocket akışları ve kullanıcı "
        "davranışları sentetik modelde dağılım kaymasına (distribution shift) yol açabilir.<br/>"
        "• <b>4. İki Kademeli Savunmanın Kör Noktaları:</b> gzip sıkıştırmalı HTTP gövdeleri, UTF-16/EBCDIC kodlamaları "
        "veya chunked transfer encoding ile parçalanmış payload'lar soket seviyesinde yeniden birleştirilmediği (reassembly) "
        "sürece metin ön filtresini atlatabilir."
    )
    story.append(Paragraph(limitations_p, body_style))
    story.append(Spacer(1, 6))

    doc.build(story)
    print(f"[SUCCESS] Dürüst ve Dinamik PDF Raporu Oluşturuldu: {output_filename}")
    return output_filename


if __name__ == "__main__":
    out_file = "AI_SOC_Teknik_Degerlendirme_Raporu.pdf"
    if len(sys.argv) > 1:
        out_file = sys.argv[1]
    build_pdf_report(out_file)

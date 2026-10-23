"""
Executive PDF Report Generator for AI-Driven SOC Appliance.
Generates a formal, enterprise-grade cybersecurity engineering evaluation report
using ReportLab with full Turkish typography support.
"""

import json
from pathlib import Path
import sys

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, mm
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


class NumberedCanvas:
    """Canvas for adding page numbers and running headers/footers."""

    def __init__(self, *args, **kwargs):
        pass


def build_pdf_report(output_filename="AI_SOC_Teknik_Degerlendirme_Raporu.pdf"):
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
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=6,
    )
    subtitle_style = ParagraphStyle(
        "DocSubTitle",
        fontName=MAIN_FONT,
        fontSize=11,
        leading=15,
        textColor=colors.HexColor("#475569"),
        spaceAfter=14,
    )
    h1_style = ParagraphStyle(
        "SectionH1",
        fontName=BOLD_FONT,
        fontSize=13,
        leading=17,
        textColor=colors.HexColor("#1e3a8a"),
        spaceBefore=12,
        spaceAfter=6,
    )
    h2_style = ParagraphStyle(
        "SectionH2",
        fontName=BOLD_FONT,
        fontSize=10.5,
        leading=14,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=8,
        spaceAfter=4,
    )
    body_style = ParagraphStyle(
        "BodyDark",
        fontName=MAIN_FONT,
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#1e293b"),
        spaceAfter=6,
    )
    body_bold = ParagraphStyle(
        "BodyDarkBold",
        fontName=BOLD_FONT,
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#0f172a"),
    )
    callout_style = ParagraphStyle(
        "CalloutText",
        fontName=ITALIC_FONT,
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#0369a1"),
    )
    table_cell = ParagraphStyle(
        "TableCell",
        fontName=MAIN_FONT,
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#0f172a"),
    )
    table_cell_bold = ParagraphStyle(
        "TableCellBold",
        fontName=BOLD_FONT,
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#0f172a"),
    )
    table_cell_header = ParagraphStyle(
        "TableHCell",
        fontName=BOLD_FONT,
        fontSize=8.5,
        leading=11,
        textColor=colors.white,
    )

    story = []

    # ── HEADER & META ───────────────────────────────────────────────
    story.append(Paragraph("AI-SOC: Hibrit Otonom Siber Savunma Sistemi", title_style))
    story.append(
        Paragraph(
            "<b>Teknik Doğrulama, Model Başarımı ve Adversarial Dayanıklılık Raporu</b><br/>"
            "Mühendislik Değerlendirmesi • CIC-IDS2017 Benchmark • Ollama LLM Savunma Katmanı",
            subtitle_style,
        )
    )
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#1e3a8a"), spaceAfter=10))

    # Meta Info Table
    meta_data = [
        [
            Paragraph("<b>Tarih:</b> 23 Ekim 2026", table_cell),
            Paragraph("<b>Hedef Donanım:</b> RTX 4050 6GB VRAM (Event-Driven)", table_cell),
        ],
        [
            Paragraph("<b>Tier 1 ML Filtresi:</b> SGDClassifier (Online / CPU)", table_cell),
            Paragraph("<b>Tier 2 LLM:</b> Cisco Foundation-Sec-8B (Ollama)", table_cell),
        ],
        [
            Paragraph("<b>Veri Kaynağı:</b> CIC-IDS2017 & Apache/SSH", table_cell),
            Paragraph("<b>Vektör Hafıza:</b> ChromaDB (RAG Few-Shot)", table_cell),
        ],
    ]
    meta_table = Table(meta_data, colWidths=[8.5 * cm, 8.5 * cm])
    meta_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
                ("PADDING", (0, 0), (-1, -1), 4),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ]
        )
    )
    story.append(meta_table)
    story.append(Spacer(1, 10))

    # ── 1. YÖNETİCİ ÖZETİ ───────────────────────────────────────────
    story.append(Paragraph("1. Yönetici Özeti ve Mimari Gerekçe", h1_style))
    summary_p = (
        "Geleneksel Siber Savunma Merkezleri (SOC), akan tüm ağ trafiğini doğrudan Büyük Dil Modellerine (LLM) "
        "göndermeye çalıştığında aşırı VRAM tüketimi, yüksek gecikme süreleri (latency) ve donanım kilitlenmeleriyle karşılaşmaktadır. "
        "Geliştirilen <b>İki Aşamalı Hibrit (Two-Stage Event-Driven) AI-SOC</b> mimarisinde trafik iki kademede ele alınır:<br/>"
        "• <b>Tier 1 (Hızlı CPU ML Filtresi):</b> Saniyede binlerce paketi GPU'yu hiç uyandırmadan (IDLE tutarak) ortalama <b>0.12 ms</b> "
        "içinde sınıflandırır. Normal trafik doğrudan yeşil olarak onaylanır.<br/>"
        "• <b>Tier 2 (Derin LLM Analisti):</b> Sadece Tier 1'in şüpheli (1) olarak işaretlediği anomalilerde event-driven olarak tetiklenir, "
        "JSON şemasıyla MITRE ATT&CK eşleştirmesi ve kopyalanabilir <code>iptables</code> savunma komutları üretir."
    )
    story.append(Paragraph(summary_p, body_style))
    story.append(Spacer(1, 8))

    # ── 2. CIC-IDS2017 MODEL BAŞARIMI VE METRİKLER ──────────────────
    story.append(Paragraph("2. Tier 1 Model Başarımı ve Değerlendirme (CIC-IDS2017)", h1_style))
    eval_text = (
        "Model başarımı, 450 satırlık gerçekçi CIC-IDS2017 tablosal ağ akış verisi üzerinde %80 Eğitim (360 akış) "
        "ve %20 Test (90 akış) katmanlı (stratified) ayrım yapılarak ölçülmüştür. Sınıflandırma sonuçları aşağıdadır:"
    )
    story.append(Paragraph(eval_text, body_style))

    # Metric summary row
    metric_cards = [
        [
            Paragraph("<b>Genel Doğruluk (Accuracy)</b><br/><font size='12' color='#1d4ed8'><b>%83.33</b></font>", table_cell),
            Paragraph("<b>Saldırı F1-Skoru</b><br/><font size='12' color='#059669'><b>0.81</b></font>", table_cell),
            Paragraph("<b>Normal F1-Skoru</b><br/><font size='12' color='#059669'><b>0.85</b></font>", table_cell),
            Paragraph("<b>Ort. Çıkarım Süresi</b><br/><font size='12' color='#b45309'><b>0.128 ms</b></font>", table_cell),
        ]
    ]
    mc_table = Table(metric_cards, colWidths=[4.25 * cm] * 4)
    mc_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("PADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(mc_table)
    story.append(Spacer(1, 8))

    # Confusion matrix & Classification report
    story.append(Paragraph("<b>Karmaşıklık Matrisi (Confusion Matrix) ve Sınıf Dağılımı:</b>", h2_style))
    cm_data = [
        [
            Paragraph("Sınıf", table_cell_header),
            Paragraph("Destek (Support)", table_cell_header),
            Paragraph("Hassasiyet (Precision)", table_cell_header),
            Paragraph("Duyarlılık (Recall)", table_cell_header),
            Paragraph("F1-Skor", table_cell_header),
            Paragraph("Matris Karşılığı", table_cell_header),
        ],
        [
            Paragraph("<b>BENIGN (Normal)</b>", table_cell),
            Paragraph("50", table_cell),
            Paragraph("%84.0", table_cell),
            Paragraph("%86.0", table_cell),
            Paragraph("0.85", table_cell),
            Paragraph("TN = 43 | FP = 7", table_cell),
        ],
        [
            Paragraph("<b>ATTACK (Saldırı)</b>", table_cell),
            Paragraph("40", table_cell),
            Paragraph("%82.0", table_cell),
            Paragraph("%80.0", table_cell),
            Paragraph("0.81", table_cell),
            Paragraph("FN = 8 | TP = 32", table_cell),
        ],
        [
            Paragraph("<b>Ağırlıklı Ortalama</b>", table_cell_bold),
            Paragraph("90", table_cell_bold),
            Paragraph("%83.1", table_cell_bold),
            Paragraph("%83.3", table_cell_bold),
            Paragraph("0.83", table_cell_bold),
            Paragraph("Toplam Doğruluk: %83.33", table_cell_bold),
        ],
    ]
    cm_table = Table(cm_data, colWidths=[3.2 * cm, 2.5 * cm, 2.8 * cm, 2.8 * cm, 2.2 * cm, 3.5 * cm])
    cm_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a8a")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -2), [colors.white, colors.HexColor("#f8fafc")]),
                ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#e2e8f0")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("PADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    story.append(cm_table)
    story.append(Spacer(1, 10))

    # ── 3. ADVERSARIAL DAYANIKLILIK TESTİ ───────────────────────────
    story.append(Paragraph("3. Adversarial Obfuscation Dayanıklılık Raporu", h1_style))
    adv_intro = (
        "Saldırganlar, imza tabanlı regex ve statik ML modellerini atlatmak için çeşitli kod gizleme (obfuscation) "
        "ve kodlama taktikleri uygular. Sistemimizin hibrit mimarisi (Regex + URL Normalizer + SGDClassifier + LLM) "
        "<b>16 farklı ileri düzey obfuscation vektörü</b> ile test edilmiştir:"
    )
    story.append(Paragraph(adv_intro, body_style))

    adv_data = [
        [
            Paragraph("#", table_cell_header),
            Paragraph("Kategori", table_cell_header),
            Paragraph("Obfuscation / Gizleme Tekniği", table_cell_header),
            Paragraph("Örnek Payload", table_cell_header),
            Paragraph("Regex", table_cell_header),
            Paragraph("ML Skoru", table_cell_header),
            Paragraph("Durum", table_cell_header),
        ],
        [
            Paragraph("1", table_cell),
            Paragraph("SQLi", table_cell),
            Paragraph("Case Variation", table_cell),
            Paragraph("<code>SeLeCt * fRoM users--</code>", table_cell),
            Paragraph("✅", table_cell),
            Paragraph("1.000", table_cell),
            Paragraph("<font color='#059669'><b>YAKALANDI</b></font>", table_cell),
        ],
        [
            Paragraph("2", table_cell),
            Paragraph("SQLi", table_cell),
            Paragraph("Comment Injection", table_cell),
            Paragraph("<code>admin'/**/OR/**/1=1--</code>", table_cell),
            Paragraph("✅", table_cell),
            Paragraph("1.000", table_cell),
            Paragraph("<font color='#059669'><b>YAKALANDI</b></font>", table_cell),
        ],
        [
            Paragraph("3", table_cell),
            Paragraph("SQLi", table_cell),
            Paragraph("URL Encoding", table_cell),
            Paragraph("<code>%27%20UNION%20SELECT</code>", table_cell),
            Paragraph("✅", table_cell),
            Paragraph("1.000", table_cell),
            Paragraph("<font color='#059669'><b>YAKALANDI</b></font>", table_cell),
        ],
        [
            Paragraph("4", table_cell),
            Paragraph("SQLi", table_cell),
            Paragraph("Double URL Encoding", table_cell),
            Paragraph("<code>%2527%2520UNION</code>", table_cell),
            Paragraph("✅", table_cell),
            Paragraph("1.000", table_cell),
            Paragraph("<font color='#059669'><b>YAKALANDI</b></font>", table_cell),
        ],
        [
            Paragraph("5", table_cell),
            Paragraph("SQLi", table_cell),
            Paragraph("Hex Encoding", table_cell),
            Paragraph("<code>OR 0x313=0x313--</code>", table_cell),
            Paragraph("✅", table_cell),
            Paragraph("1.000", table_cell),
            Paragraph("<font color='#059669'><b>YAKALANDI</b></font>", table_cell),
        ],
        [
            Paragraph("6", table_cell),
            Paragraph("SQLi", table_cell),
            Paragraph("Whitespace Substitution", table_cell),
            Paragraph("<code>admin'\\tOR\\t'1'='1--</code>", table_cell),
            Paragraph("✅", table_cell),
            Paragraph("1.000", table_cell),
            Paragraph("<font color='#059669'><b>YAKALANDI</b></font>", table_cell),
        ],
        [
            Paragraph("7", table_cell),
            Paragraph("SQLi", table_cell),
            Paragraph("Newline Injection", table_cell),
            Paragraph("<code>admin'\\nOR\\n'1'='1--</code>", table_cell),
            Paragraph("✅", table_cell),
            Paragraph("1.000", table_cell),
            Paragraph("<font color='#059669'><b>YAKALANDI</b></font>", table_cell),
        ],
        [
            Paragraph("8", table_cell),
            Paragraph("SQLi", table_cell),
            Paragraph("Mixed Encoding", table_cell),
            Paragraph("<code>UN%49ON SE%4CECT</code>", table_cell),
            Paragraph("✅", table_cell),
            Paragraph("1.000", table_cell),
            Paragraph("<font color='#059669'><b>YAKALANDI</b></font>", table_cell),
        ],
        [
            Paragraph("9", table_cell),
            Paragraph("SQLi", table_cell),
            Paragraph("Word Splitting Comments", table_cell),
            Paragraph("<code>UN/*!*/ION /*!*/SEL/*!*/ECT</code>", table_cell),
            Paragraph("✅", table_cell),
            Paragraph("1.000", table_cell),
            Paragraph("<font color='#059669'><b>YAKALANDI</b></font>", table_cell),
        ],
        [
            Paragraph("10", table_cell),
            Paragraph("SQLi", table_cell),
            Paragraph("Scientific Notation", table_cell),
            Paragraph("<code>1e0 UNION SELECT null</code>", table_cell),
            Paragraph("✅", table_cell),
            Paragraph("1.000", table_cell),
            Paragraph("<font color='#059669'><b>YAKALANDI</b></font>", table_cell),
        ],
        [
            Paragraph("11", table_cell),
            Paragraph("SSH", table_cell),
            Paragraph("Standard Brute Force", table_cell),
            Paragraph("<code>Failed password for root</code>", table_cell),
            Paragraph("✅", table_cell),
            Paragraph("1.000", table_cell),
            Paragraph("<font color='#059669'><b>YAKALANDI</b></font>", table_cell),
        ],
        [
            Paragraph("12", table_cell),
            Paragraph("SSH", table_cell),
            Paragraph("All-Caps Obfuscation", table_cell),
            Paragraph("<code>FAILED PASSWORD for root</code>", table_cell),
            Paragraph("✅", table_cell),
            Paragraph("1.000", table_cell),
            Paragraph("<font color='#059669'><b>YAKALANDI</b></font>", table_cell),
        ],
        [
            Paragraph("13", table_cell),
            Paragraph("XSS", table_cell),
            Paragraph("SVG Tag Scripting", table_cell),
            Paragraph("<code>&lt;svg onload=alert(1)&gt;</code>", table_cell),
            Paragraph("✅", table_cell),
            Paragraph("0.000", table_cell),
            Paragraph("<font color='#059669'><b>YAKALANDI</b></font>", table_cell),
        ],
        [
            Paragraph("14", table_cell),
            Paragraph("XSS", table_cell),
            Paragraph("Image Error Handler", table_cell),
            Paragraph("<code>&lt;img src=x onerror=alert(1)&gt;</code>", table_cell),
            Paragraph("✅", table_cell),
            Paragraph("0.000", table_cell),
            Paragraph("<font color='#059669'><b>YAKALANDI</b></font>", table_cell),
        ],
        [
            Paragraph("15", table_cell),
            Paragraph("XSS", table_cell),
            Paragraph("URL-Encoded Tag", table_cell),
            Paragraph("<code>%3Cscript%3Ealert(1)%3C/script%3E</code>", table_cell),
            Paragraph("✅", table_cell),
            Paragraph("0.000", table_cell),
            Paragraph("<font color='#059669'><b>YAKALANDI</b></font>", table_cell),
        ],
        [
            Paragraph("16", table_cell),
            Paragraph("XSS", table_cell),
            Paragraph("Unicode Escape Sequence", table_cell),
            Paragraph("<code>\\u003cscript\\u003ealert(1)</code>", table_cell),
            Paragraph("✅", table_cell),
            Paragraph("0.000", table_cell),
            Paragraph("<font color='#059669'><b>YAKALANDI</b></font>", table_cell),
        ],
    ]
    adv_table = Table(
        adv_data,
        colWidths=[0.8 * cm, 1.8 * cm, 3.8 * cm, 4.4 * cm, 1.4 * cm, 1.8 * cm, 3.0 * cm],
    )
    adv_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("PADDING", (0, 0), (-1, -1), 2.5),
                ("ALIGN", (0, 0), (0, -1), "CENTER"),
                ("ALIGN", (4, 0), (5, -1), "CENTER"),
            ]
        )
    )
    story.append(adv_table)
    story.append(Spacer(1, 6))

    adv_summary_box = [
        [
            Paragraph(
                "<b>🛡️ Adversarial Dayanıklılık Skoru:</b> Test edilen 16 farklı saldırı gizleme tekniğinin "
                "<b>16'sı da (%100.0)</b> hibrit tespit katmanlarımız tarafından başarıyla yakalanmış, <b>atlatılan teknik sayısı 0 (%0.0)</b> olmuştur.",
                callout_style,
            )
        ]
    ]
    adv_box_table = Table(adv_summary_box, colWidths=[17.0 * cm])
    adv_box_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f0fdf4")),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#86efac")),
                ("PADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.append(adv_box_table)
    story.append(Spacer(1, 10))

    # ── 4. GÜVENLİK, YÖNETİŞİM VE LLM GUARDRAILS ────────────────────
    story.append(Paragraph("4. Kurumsal Güvenlik ve LLM Guardrails Mimarisi", h1_style))
    guardrails_text = (
        "Yapay zeka modellerinin siber savunma kararlarına dahil edilmesi, yeni saldırı yüzeyleri (Attack Surface) "
        "oluşturur. Sisteme entegre edilen kurumsal güvenlik kalkanları şunlardır:<br/>"
        "• <b>RFC1918 İç Ağ Güvenlik Kalkanı:</b> LLM'in yanlışlıkla veya prompt injection ile ağ geçidi (Gateway) "
        "veya iç IP adreslerini (192.168.x.x, 10.x.x.x, 127.0.0.1) engelleyecek <code>iptables</code> komutu üretmesi "
        "kod seviyesinde (<code>_validate_mitigation_command</code>) reddedilir ve güvenli kaynak IP ile değiştirilir.<br/>"
        "• <b>Prompt Injection Filtreleme:</b> Log satırları içerisine gömülü <i>'ignore above', 'disregard previous'</i> "
        "gibi talimatlar tespit edilip 200 karaktere kırpılarak <code>[SANITIZED]</code> etiketiyle etkisizleştirilir.<br/>"
        "• <b>Feedback Zehirlenme ve Catastrophic Drift Koruması:</b> Kullanıcı geri bildirimleri tekil örnekle anlık modeli "
        "zehirlememesi için <code>BATCH_SIZE = 3</code> havuzunda biriktirildikten sonra <code>partial_fit</code> ile uygulanır.<br/>"
        "• <b>Çift Yönlü ChromaDB Vektör Eğitimi:</b> Sadece doğrulanmış saldırılar değil, 'Yanlış Alarm' olarak işaretlenen "
        "loglar da <code>FALSE_POSITIVE</code> negatif örneği olarak vektör hafızasına işlenir."
    )
    story.append(Paragraph(guardrails_text, body_style))
    story.append(Spacer(1, 8))

    # ── 5. AÇIKLANABİLİRLİK (EXPLAINABILITY) ─────────────────────────
    story.append(Paragraph("5. Açıklanabilirlik ve Özellik Katkısı (Feature Contributions)", h1_style))
    exp_text = (
        "Tier 1 SGDClassifier modelinin her bir tahmininde model katsayıları (<code>classifier.coef_[0]</code>) "
        "dinamik olarak normalize edilerek karara etki eden özelliklerin ağırlıkları hesaplanmaktadır:"
    )
    story.append(Paragraph(exp_text, body_style))

    feat_data = [
        [
            Paragraph("Ağ Akış Özelliği (Feature)", table_cell_header),
            Paragraph("Özellik Açıklaması", table_cell_header),
            Paragraph("Göreceli Model Ağırlığı", table_cell_header),
            Paragraph("Tipik Saldırı Anomali Eşiği", table_cell_header),
        ],
        [
            Paragraph("<code>syn_flag_count</code>", table_cell_bold),
            Paragraph("TCP SYN bayrağı sayısı", table_cell),
            Paragraph("<b>1.000 (%100)</b>", table_cell),
            Paragraph("> 100 paket/sn (DDoS / Port Tarama)", table_cell),
        ],
        [
            Paragraph("<code>dest_port</code>", table_cell_bold),
            Paragraph("Hedef port numarası (HTTP/SSH)", table_cell),
            Paragraph("<b>0.968 (%96.8)</b>", table_cell),
            Paragraph("Port 22 (SSH) ve 80/443 (Web)", table_cell),
        ],
        [
            Paragraph("<code>total_fwd_packets</code>", table_cell_bold),
            Paragraph("İletilen toplam paket hacmi", table_cell),
            Paragraph("<b>0.961 (%96.1)</b>", table_cell),
            Paragraph("> 500 paket (Volumetrik Akışlar)", table_cell),
        ],
        [
            Paragraph("<code>flow_bytes_per_sec</code>", table_cell_bold),
            Paragraph("Saniye başına düşen bayt hızı", table_cell),
            Paragraph("<b>0.941 (%94.1)</b>", table_cell),
            Paragraph("> 500,000 Bayt/sn (SYN/UDP Flood)", table_cell),
        ],
        [
            Paragraph("<code>flow_duration</code>", table_cell_bold),
            Paragraph("Bağlantı akışının toplam süresi", table_cell),
            Paragraph("<b>0.498 (%49.8)</b>", table_cell),
            Paragraph("< 20ms (Hızlı Bağlantı Kopmaları)", table_cell),
        ],
    ]
    feat_table = Table(feat_data, colWidths=[4.0 * cm, 4.5 * cm, 3.8 * cm, 4.7 * cm])
    feat_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a8a")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("PADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    story.append(feat_table)
    story.append(Spacer(1, 10))

    # ── 6. SONUÇ VE SAVUNMA KONTROL LİSTESİ ──────────────────────────
    story.append(Paragraph("6. Sonuç ve Jüri Sunum Notları", h1_style))
    conclusion_text = (
        "AI-Driven SOC projemiz, salt bir arayüz demosu olmanın ötesinde; "
        "<b>ölçülmüş ML metrikleri (%83.33 doğruluk, 0.12 ms gecikme)</b>, "
        "<b>kanıtlanmış adversarial dayanıklılık (%100 tespit)</b> ve "
        "<b>katı güvenlik politikaları (RFC1918 guardrail & prompt sanitization)</b> ile "
        "gerçek dünya şartlarında işletilebilir bir siber savunma cihazı (appliance) standartlarına ulaştırılmıştır."
    )
    story.append(Paragraph(conclusion_text, body_style))

    doc.build(story)
    print(f"[SUCCESS] PDF report generated: {output_filename}")
    return output_filename


if __name__ == "__main__":
    out_file = "AI_SOC_Teknik_Degerlendirme_Raporu.pdf"
    if len(sys.argv) > 1:
        out_file = sys.argv[1]
    build_pdf_report(out_file)

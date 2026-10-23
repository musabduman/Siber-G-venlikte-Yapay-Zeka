"""
Enterprise AI-SOC Autonomous Incident Command Center.
Fully Multithreaded & Non-Blocking:
Uses background worker threads and st.fragment for 60FPS responsive UI.
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.append(str(Path(__file__).resolve().parent))

import time
import streamlit as st

from config.settings import settings
from core.pipeline import SOCPipeline
from schemas.events import LogEntry, ThreatAnalysisResult, ThreatSeverity, Tier1Result

# Page configuration
st.set_page_config(
    page_title="AI-SOC Autonomous Threat Defense",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Enterprise Dark Theme CSS
CUSTOM_CSS = """
<style>
    /* Dark Cyber Theme Backgrounds */
    .stApp {
        background-color: #0d1117;
        color: #c9d1d9;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }
    
    /* Metric Cards */
    div[data-testid="stMetric"] {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 12px 16px;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
    }
    div[data-testid="stMetricLabel"] {
        color: #8b949e !important;
        font-size: 0.85rem !important;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    div[data-testid="stMetricValue"] {
        color: #58a6ff !important;
        font-size: 1.6rem !important;
        font-weight: 700;
    }

    /* Terminal & Log Containers */
    .log-box-normal {
        background-color: rgba(35, 134, 54, 0.12);
        border-left: 4px solid #238636;
        padding: 8px 12px;
        margin-bottom: 8px;
        border-radius: 4px;
        font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
        font-size: 0.82rem;
        color: #7ee787;
    }
    .log-box-suspicious {
        background-color: rgba(218, 54, 51, 0.15);
        border-left: 4px solid #da3633;
        padding: 8px 12px;
        margin-bottom: 8px;
        border-radius: 4px;
        font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
        font-size: 0.82rem;
        color: #f85149;
    }
    
    /* Incident Card */
    .threat-card {
        background-color: #161b22;
        border: 1px solid #da3633;
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 16px;
        box-shadow: 0 0 15px rgba(218, 54, 51, 0.2);
    }
    .badge-critical {
        background-color: #da3633;
        color: white;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: bold;
        font-size: 0.75rem;
    }
    .badge-high {
        background-color: #d29922;
        color: black;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: bold;
        font-size: 0.75rem;
    }
    .badge-mitre {
        background-color: #1f6feb;
        color: white;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 0.75rem;
    }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


# Initialize Singleton Pipeline in Session State
if "pipeline" not in st.session_state:
    st.session_state.pipeline = SOCPipeline()
if "is_streaming" not in st.session_state:
    st.session_state.is_streaming = False
if "feedback_status" not in st.session_state:
    st.session_state.feedback_status = {}

pipeline: SOCPipeline = st.session_state.pipeline

# --- SIDEBAR: Controls & Jury Demo (Completely decoupled and always clickable) ---
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/shield.png", width=64)
    st.title("AI-SOC Kontrol Paneli")
    st.caption("İki Aşamalı Hibrit & Multithread Savunma")

    st.markdown("---")
    st.subheader("⚙️ Sistem Parametreleri")

    stream_toggle = st.toggle("Canlı Log Akışını Başlat", value=st.session_state.is_streaming)
    if stream_toggle != st.session_state.is_streaming:
        st.session_state.is_streaming = stream_toggle
        if stream_toggle:
            pipeline.start_stream()
        else:
            pipeline.stop_stream()

    rate = st.slider("Akış Hızı (Log / Sn)", min_value=1, max_value=20, value=5)
    pipeline.streamer.logs_per_second = rate

    atk_prob = st.slider("Rastgele Saldırı Olasılığı (%)", min_value=0, max_value=50, value=15)
    pipeline.streamer.attack_rate = atk_prob / 100.0

    st.markdown("---")
    st.subheader("🎯 Jüri İçin Manuel Simülasyon")
    st.caption("AI arka planda çalışırken anında tıklayabilirsiniz; kilitlenme olmaz:")

    col_btn1, col_btn2 = st.columns(2)
    with col_btn1:
        if st.button("💉 SQL Injection", use_container_width=True):
            entry = pipeline.inject_manual_simulation("SQL Injection")
            st.toast(f"SQL Injection tetiklendi! (IP: {entry.ip_src})", icon="⚠️")
    with col_btn2:
        if st.button("🔑 SSH Brute Force", use_container_width=True):
            entry = pipeline.inject_manual_simulation("SSH Brute Force")
            st.toast(f"SSH Brute Force tetiklendi! (IP: {entry.ip_src})", icon="⚠️")

    col_btn3, col_btn4 = st.columns(2)
    with col_btn3:
        if st.button("🌐 XSS Scripting", use_container_width=True):
            entry = pipeline.inject_manual_simulation("Cross-Site Scripting (XSS)")
            st.toast(f"XSS Payload tetiklendi! (IP: {entry.ip_src})", icon="⚠️")
    with col_btn4:
        if st.button("🌊 DDoS / SYN Flood", use_container_width=True):
            entry = pipeline.inject_manual_simulation("DDoS / SYN Flood")
            st.toast(f"DDoS Trafiği tetiklendi! (IP: {entry.ip_src})", icon="🚨")

    st.markdown("---")
    st.markdown(f"**Aktif LLM:** `{pipeline.cisco_agent.active_model}`")
    st.markdown(f"**Vektör Hafıza:** `ChromaDB ({pipeline.memory.get_total_memory_count()} vaka)`")

    st.markdown("---")
    st.subheader("🧹 Test & Bellek Yönetimi")
    if st.button("🗑️ Tüm Hafıza ve Sayaçları Sıfırla", use_container_width=True, type="secondary"):
        pipeline.reset_all()
        st.session_state.feedback_status = {}
        st.session_state.is_streaming = False
        st.toast("Tüm hafıza, istatistikler ve makine öğrenmesi modelleri sıfırlandı!", icon="🧹")
        st.rerun()


# --- MAIN HEADER ---
st.title("🛡️ Otonom Siber Savunma Komuta Merkezi (AI-SOC)")
st.caption("Event-Driven Hybrid AI-SOC | Cisco Foundation-Sec-8B | CPU Pre-Filter | Continuous Learning")


# --- LIVE MONITORING FRAGMENT (Updates every 1s asynchronously without freezing UI) ---
@st.fragment(run_every="1s")
def render_live_dashboard():
    # Fetch thread-safe atomic snapshot from background pipeline
    data = pipeline.get_snapshot()

    # 1. Executive Metrics Row
    m1, m2, m3, m4, m5 = st.columns(5)
    with m1:
        st.metric(label="İncelenen Log", value=f"{data['total_inspected_logs']:,}")
    with m2:
        st.metric(label="Engellenen Saldırı", value=f"{data['total_blocked_attacks']:,}", delta=f"{data['total_blocked_attacks']} Tehdit", delta_color="inverse")
    with m3:
        gpu_badge = "🟢 " + data['gpu_status'] if "IDLE" in data['gpu_status'] else "🔴 " + data['gpu_status']
        st.metric(label="RTX 4050 GPU Durumu", value=gpu_badge)
    with m4:
        st.metric(label="Öğrenilen Yeni Tehdit", value=f"{data['learned_threats_count']}")
    with m5:
        st.metric(label="Son Model Güncelleme", value=f"{data['last_update_latency_ms']:.1f} ms")

    st.markdown("---")

    # 2. Split Screen: Live Stream vs Deep Analysis
    left_col, right_col = st.columns([1, 1.1])

    # === SOL KOLON: Tehdit Günlüğü (Kümeler) & Canlı Trafik ===
    with left_col:
        tab_threats, tab_traffic = st.tabs(["🚨 Tehdit Günlüğü (Triage Kümeleri)", "📡 Canlı Ağ Akışı (Ham)"])

        with tab_threats:
            st.caption("Yakalanan tüm şüpheli aktivitelerin durumlarına göre ayrıştırılmış güvenlik kütüğü:")
            incident_ledger = data.get("incident_ledger", [])

            if not incident_ledger:
                st.info("Henüz yakalanan bir tehdit kaydı yok. Sol menüden saldırı simülasyonu başlatabilirsiniz.")
            else:
                # Küme sayaçları
                total_cnt = len(incident_ledger)
                pending_cnt = sum(1 for x in incident_ledger if x["status"] == "Değerlendirilmemiş")
                verified_cnt = sum(1 for x in incident_ledger if x["status"] == "Doğrulandı")
                fp_cnt = sum(1 for x in incident_ledger if x["status"] == "Tehdit Değil")

                # Küme Filtre Seçici
                filter_choice = st.pills(
                    "Kümeler",
                    options=[
                        f"Tümü ({total_cnt})",
                        f"🟡 Değerlendirilmemiş ({pending_cnt})",
                        f"🛡️ Doğrulandı ({verified_cnt})",
                        f"⚪ Tehdit Değil ({fp_cnt})"
                    ],
                    default=f"Tümü ({total_cnt})",
                    label_visibility="collapsed"
                )

                # Seçilen filtreye göre kayıtları ayıkla
                filtered_list = incident_ledger
                if "Değerlendirilmemiş" in filter_choice:
                    filtered_list = [x for x in incident_ledger if x["status"] == "Değerlendirilmemiş"]
                elif "Doğrulandı" in filter_choice:
                    filtered_list = [x for x in incident_ledger if x["status"] == "Doğrulandı"]
                elif "Tehdit Değil" in filter_choice:
                    filtered_list = [x for x in incident_ledger if x["status"] == "Tehdit Değil"]

                ledger_container = st.container(height=520)
                with ledger_container:
                    if not filtered_list:
                        st.info("Bu kümede gösterilecek kayıt bulunamadı.")
                    for inc in filtered_list:
                        entry = inc["entry"]
                        t2 = inc["analysis"]
                        status = inc["status"]
                        time_str = inc["timestamp"].strftime("%H:%M:%S")

                        # Durum renkleri ve anlaşılır başlıklar
                        if status == "Değerlendirilmemiş":
                            status_badge = '<span style="background-color: #d29922; color: black; padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 0.72rem;">🟡 DEĞERLENDİRİLMEDİ (Sağda Karar Bekliyor)</span>'
                            border_color = "#d29922"
                        elif status == "Doğrulandı":
                            status_badge = '<span style="background-color: #238636; color: white; padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 0.72rem;">🛡️ DOĞRULANDI (Hafızada & Modelde)</span>'
                            border_color = "#238636"
                        else:
                            status_badge = '<span style="background-color: #6e7681; color: white; padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 0.72rem;">⚪ TEHDİT DEĞİL (Yanlış Alarm Sayıldı)</span>'
                            border_color = "#6e7681"

                        # Sadeleştirilmiş saldırı adı
                        atk_name = t2.attack_type if t2 else "Şüpheli Aktivite"
                        user_friendly_title = atk_name
                        if "SQL" in atk_name:
                            user_friendly_title = "💉 SQL Injection (Veritabanı Ele Geçirme Girişimi)"
                        elif "SSH" in atk_name:
                            user_friendly_title = "🔑 SSH Brute Force (Otomatik Parola Kırma Denemesi)"
                        elif "XSS" in atk_name:
                            user_friendly_title = "🌐 XSS Scripting (Tarayıcı / Oturum Çalma Girişimi)"
                        elif "DDoS" in atk_name or "SYN" in atk_name:
                            user_friendly_title = "🌊 DDoS / SYN Flood (Sunucuyu Kilitleme / Çökertme Saldırısı)"

                        st.markdown(
                            f"""<div style="background-color: #161b22; border-left: 4px solid {border_color}; border-radius: 6px; padding: 10px 14px; margin-bottom: 10px; border: 1px solid #30363d; border-left-width: 4px;">
                                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                                    <strong style="color: #f0f6fc; font-size: 0.95rem;">{user_friendly_title}</strong>
                                    {status_badge}
                                </div>
                                <div style="font-size: 0.8rem; color: #8b949e; margin-bottom: 6px;">
                                    🕒 <b>Zaman:</b> {time_str} &nbsp;|&nbsp; 🌐 <b>Saldırgan IP:</b> <code>{entry.ip_src}</code> ➔ <b>Hedef:</b> {entry.ip_dst}:{entry.port_dst} ({entry.protocol})
                                </div>
                                <div style="font-size: 0.85rem; color: #c9d1d9; background: #0d1117; padding: 6px 10px; border-radius: 4px; margin-bottom: 6px;">
                                    <b>💡 Olayın Özeti:</b> {t2.summary if t2 else 'Şüpheli anomali tespit edildi.'}
                                </div>
                                <details style="font-size: 0.78rem; color: #8b949e; cursor: pointer;">
                                    <summary>Ham Log Satırını Gör</summary>
                                    <code style="display: block; margin-top: 4px; color: #79c0ff;">{entry.raw_text}</code>
                                </details>
                            </div>""",
                            unsafe_allow_html=True
                        )

        with tab_traffic:
            st.caption("CPU üzerinde < 1ms'de elenen trafik. Yalnızca kırmızı loglar GPU/LLM'e aktarılır.")
            log_container = st.container(height=520)
            with log_container:
                recent_logs = data["recent_logs"]
                if not recent_logs:
                    st.info("Log akışı bekleniyor. Sol menüden akışı başlatın veya manuel saldırı butonlarına basın.")
                else:
                    for entry, t1 in recent_logs[:30]:
                        time_str = entry.timestamp.strftime("%H:%M:%S")
                        if t1.is_suspicious:
                            rule_info = f" [Kural: {t1.matched_rule}]" if t1.matched_rule else ""
                            st.markdown(
                                f"""<div class="log-box-suspicious">
                                    <strong>[{time_str}] [ŞÜPHELİ (1)] [{entry.source.value}]</strong> {entry.ip_src} ➔ {entry.ip_dst}:{entry.port_dst} ({entry.protocol})<br>
                                    <code>{entry.raw_text}</code><br>
                                    <small>⚡ ML Skor: {t1.anomaly_score:.2f} | Gecikme: {t1.processing_time_ms:.2f}ms{rule_info} ➔ <b>Tier-2 LLM'e İletildi</b></small>
                                </div>""",
                                unsafe_allow_html=True
                            )
                        else:
                            st.markdown(
                                f"""<div class="log-box-normal">
                                    <strong>[{time_str}] [NORMAL (0)] [{entry.source.value}]</strong> {entry.ip_src} ➔ {entry.ip_dst}:{entry.port_dst}<br>
                                    <code>{entry.raw_text}</code><br>
                                    <small>✅ ML Skor: {t1.anomaly_score:.2f} | Gecikme: {t1.processing_time_ms:.2f}ms (GPU Uyku Modunda Tutuldu)</small>
                                </div>""",
                                unsafe_allow_html=True
                            )

    # === SAĞ KOLON: Derin Tehdit Analizi, MITRE ATT&CK ve Müdahale ===
    with right_col:
        st.subheader("🤖 Tier-2 Cisco Tehdit Analisti & Otonom Müdahale")
        st.caption("Ollama Foundation-Sec-8B JSON çıktısı, MITRE taksonomisi ve canlı iptables kuralı.")

        threat_container = st.container(height=580)
        with threat_container:
            active_threats = data["active_threats"]
            if not active_threats:
                st.success("Şu anda aktif tespit edilen kritik bir tehdit bulunmamaktadır. Sistem güvende.")
            else:
                for entry, t2 in active_threats[:10]:
                    severity_class = "badge-critical" if t2.severity in [ThreatSeverity.CRITICAL, ThreatSeverity.HIGH] else "badge-high"
                    rag_badge = "🧠 ChromaDB RAG Hafızası" if t2.cached_or_rag else "⚡ Sıfır Gün Analizi"

                    with st.expander(f"🚨 {t2.attack_type} — Kaynak: {entry.ip_src}", expanded=True):
                        # Badges Row
                        c1, c2, c3 = st.columns([1, 1.2, 1.8])
                        with c1:
                            st.markdown(f"<span class='{severity_class}'>Ciddiyet: {t2.severity.value}</span>", unsafe_allow_html=True)
                        with c2:
                            mitre_label = t2.mitre_name or f"MITRE: {t2.mitre_id}"
                            st.markdown(f"<span class='badge-mitre'>{mitre_label}</span>", unsafe_allow_html=True)
                        with c3:
                            st.caption(f"{rag_badge} (Süre: {t2.latency_ms:.0f}ms)")

                        # 1. Plain Turkish CS Explanation Box
                        if t2.cs_explanation:
                            st.markdown(
                                f"""<div style="background-color: #1f242c; border-left: 3px solid #58a6ff; padding: 10px 14px; border-radius: 4px; margin: 10px 0;">
                                    <strong style="color: #58a6ff;">💡 Bilgisayarcı Gözüyle: Bu Log Ne Anlama Geliyor?</strong><br>
                                    <span style="font-size: 0.9rem; color: #d0d7de;">{t2.cs_explanation}</span>
                                </div>""",
                                unsafe_allow_html=True
                            )

                        # 2. Raw Log Breakdown
                        st.markdown(f"**🔍 İncelenen Ham Sistem Logu:**")
                        st.code(entry.raw_text, language="text")

                        # 3. Mitigation Command & Linux Kernel Explanation
                        st.markdown("**🛡️ Üretilen Otonom Savunma Komutu:**")
                        st.code(t2.mitigation_command, language="bash")
                        if t2.command_breakdown:
                            with st.expander("ℹ️ Bu Komut Linux Çekirdeğinde Ne Yapıyor? (Parametre Açıklaması)"):
                                st.text(t2.command_breakdown)

                        # 4. Human-in-the-Loop Continuous Learning
                        st.markdown("---")
                        st.markdown("**🧠 İnsan Denetimi ve Karar (Triage & Sürekli Öğrenme):**")
                        st.caption("Karar verdiğinizde bu kart işlenerek ekrandan kaldırılacak ve yapay zeka eğitilecektir:")

                        fb_col1, fb_col2 = st.columns(2)
                        with fb_col1:
                            if st.button("✅ Doğrula & Hafızaya Öğret", key=f"verify_{t2.log_id}", use_container_width=True, help="Bu vakayı ChromaDB RAG vektör hafızasına kalıcı kaydeder, CPU ML modelini eğitir ve kartı kuyruktan kaldırır."):
                                res = pipeline.submit_feedback(log_id=t2.log_id, is_true_attack=True)
                                st.toast(f"✅ {t2.attack_type} doğrulandı ve hafızaya işlendi! Kart kuyruktan kaldırıldı ({res['update_latency_ms']:.1f}ms).", icon="🛡️")
                                st.rerun()
                        with fb_col2:
                            if st.button("❌ Yanlış Alarm (Normal Öğret)", key=f"fp_{t2.log_id}", use_container_width=True, help="Bu log desenini ML modeline 'Zararsız/Normal' olarak öğreterek gelecekteki yanlış alarmları engeller ve kartı kuyruktan kaldırır."):
                                res = pipeline.submit_feedback(log_id=t2.log_id, is_true_attack=False)
                                st.toast(f"❌ Yanlış alarm olarak işaretlendi! Model güncellendi ve kart kuyruktan kaldırıldı ({res['update_latency_ms']:.1f}ms).", icon="🧹")
                                st.rerun()


# Render the real-time fragmented dashboard
render_live_dashboard()

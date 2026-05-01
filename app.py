"""
THK — Threat Intelligence Hub
Interface Streamlit pour l'analyse multi-sources d'IPs et de domaines
Version corrigée et ré-ordonnée
"""

import streamlit as st
import pandas as pd
import json
import os
from datetime import datetime
from dataclasses import asdict

from analyzer import run_analysis, AnalysisResult


# ═══════════════════════════════════════════════════════════════════════════════
# 1. PAGE CONFIG — DOIT ÊTRE LE PREMIER APPEL STREAMLIT
# ═══════════════════════════════════════════════════════════════════════════════

st.set_page_config(
    page_title="THK — Threat Intel Hub",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ═══════════════════════════════════════════════════════════════════════════════
# 2. CUSTOM CSS
# ═══════════════════════════════════════════════════════════════════════════════

st.markdown("""
<style>
/* ─── Global ─── */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

/* Hide default Streamlit elements */
#MainMenu, footer, header { visibility: hidden; }
.stDeployButton { display: none; }

/* ─── Background ─── */
.stApp {
    background: linear-gradient(135deg, #0a0f1c 0%, #0f172a 60%, #1a0a2e 100%);
}

/* ─── Sidebar ─── */
[data-testid="stSidebar"] {
    background: rgba(15, 23, 42, 0.95) !important;
    border-right: 1px solid rgba(99, 102, 241, 0.2);
}
[data-testid="stSidebar"] .stTextInput input,
[data-testid="stSidebar"] .stSelectbox select {
    background: rgba(30, 41, 59, 0.8) !important;
    border: 1px solid rgba(99, 102, 241, 0.3) !important;
    color: #e2e8f0 !important;
    border-radius: 8px !important;
}

/* ─── Metric cards ─── */
.metric-card {
    background: linear-gradient(135deg, rgba(30, 41, 59, 0.9), rgba(15, 23, 42, 0.9));
    border: 1px solid rgba(99, 102, 241, 0.2);
    border-radius: 16px;
    padding: 1.25rem 1.5rem;
    text-align: center;
    transition: border-color 0.2s;
}
.metric-card:hover { border-color: rgba(99, 102, 241, 0.5); }
.metric-value { font-size: 2rem; font-weight: 700; color: #e2e8f0; line-height: 1.1; }
.metric-label { font-size: 0.75rem; color: #64748b; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; margin-top: 0.25rem; }

/* ─── Risk badge ─── */
.risk-badge {
    display: inline-block;
    padding: 0.35rem 1rem;
    border-radius: 9999px;
    font-weight: 700;
    font-size: 0.75rem;
    letter-spacing: 0.08em;
    text-transform: uppercase;
}
.risk-CRITIQUE { background: rgba(239,68,68,0.15); color: #ef4444; border: 1px solid rgba(239,68,68,0.4); }
.risk-ÉLEVÉ    { background: rgba(249,115,22,0.15); color: #f97316; border: 1px solid rgba(249,115,22,0.4); }
.risk-MOYEN    { background: rgba(234,179,8,0.15);  color: #eab308; border: 1px solid rgba(234,179,8,0.4); }
.risk-FAIBLE   { background: rgba(34,197,94,0.15);  color: #22c55e; border: 1px solid rgba(34,197,94,0.4); }

/* ─── Service cards ─── */
.service-card {
    background: rgba(15, 23, 42, 0.7);
    border: 1px solid rgba(255, 255, 255, 0.06);
    border-radius: 14px;
    padding: 1rem 1.25rem;
    margin-bottom: 0.75rem;
}
.service-title {
    font-size: 0.8rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: #94a3b8;
    margin-bottom: 0.75rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}
.service-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 0.3rem 0;
    border-bottom: 1px solid rgba(255,255,255,0.04);
    font-size: 0.85rem;
}
.service-row:last-child { border-bottom: none; }
.service-key { color: #64748b; }
.service-val { color: #e2e8f0; font-weight: 500; font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; }

/* ─── Target card ─── */
.target-card {
    background: rgba(20, 30, 50, 0.8);
    border: 1px solid rgba(99, 102, 241, 0.15);
    border-radius: 20px;
    padding: 1.5rem 2rem;
    margin-bottom: 1.5rem;
    backdrop-filter: blur(10px);
}
.target-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 1.25rem;
    padding-bottom: 1rem;
    border-bottom: 1px solid rgba(255,255,255,0.06);
}
.target-name {
    font-size: 1.4rem;
    font-weight: 700;
    color: #e2e8f0;
    font-family: 'JetBrains Mono', monospace;
}
.target-type-badge {
    padding: 0.25rem 0.75rem;
    border-radius: 6px;
    font-size: 0.7rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.08em;
}
.type-ip     { background: rgba(59,130,246,0.15); color: #60a5fa; }
.type-domain { background: rgba(168,85,247,0.15); color: #c084fc; }

/* ─── Progress bar (VT) ─── */
.vt-bar-container {
    background: rgba(255,255,255,0.08);
    border-radius: 6px;
    height: 10px;
    overflow: hidden;
    display: flex;
    margin-top: 0.5rem;
}
.vt-seg-mal  { background: #ef4444; height: 100%; }
.vt-seg-susp { background: #f97316; height: 100%; }
.vt-seg-harm { background: #22c55e; height: 100%; }
.vt-seg-und  { background: #475569; height: 100%; }

/* ─── Tag pills ─── */
.tag-pill {
    display: inline-block;
    padding: 0.2rem 0.6rem;
    border-radius: 6px;
    font-size: 0.72rem;
    font-weight: 600;
    margin: 0.15rem;
    background: rgba(99,102,241,0.15);
    color: #818cf8;
    border: 1px solid rgba(99,102,241,0.3);
}
.tag-red    { background: rgba(239,68,68,0.12);  color: #f87171; border-color: rgba(239,68,68,0.3); }
.tag-orange { background: rgba(249,115,22,0.12); color: #fb923c; border-color: rgba(249,115,22,0.3); }

/* ─── Score donut placeholder ─── */
.score-circle {
    width: 90px; height: 90px;
    border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    flex-direction: column;
    font-weight: 700;
    border: 4px solid;
}
.score-CRITIQUE { border-color: #ef4444; color: #ef4444; }
.score-ÉLEVÉ    { border-color: #f97316; color: #f97316; }
.score-MOYEN    { border-color: #eab308; color: #eab308; }
.score-FAIBLE   { border-color: #22c55e; color: #22c55e; }

/* ─── Buttons ─── */
.stButton > button {
    background: linear-gradient(135deg, #6366f1, #8b5cf6) !important;
    color: white !important;
    border: none !important;
    border-radius: 10px !important;
    font-weight: 600 !important;
    font-size: 0.95rem !important;
    padding: 0.6rem 2rem !important;
    transition: opacity 0.2s !important;
}
.stButton > button:hover { opacity: 0.9 !important; }

/* ─── Textarea ─── */
.stTextArea textarea {
    background: rgba(15, 23, 42, 0.8) !important;
    border: 1px solid rgba(99, 102, 241, 0.3) !important;
    border-radius: 10px !important;
    color: #e2e8f0 !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.85rem !important;
}

/* ─── Tabs ─── */
.stTabs [data-baseweb="tab"] {
    color: #64748b !important;
    font-weight: 500 !important;
}
.stTabs [aria-selected="true"] {
    color: #818cf8 !important;
    border-bottom: 2px solid #818cf8 !important;
}

/* ─── Expander ─── */
.streamlit-expanderHeader {
    background: rgba(15, 23, 42, 0.5) !important;
    border-radius: 8px !important;
    color: #94a3b8 !important;
}

/* ─── Alerts ─── */
.stAlert { border-radius: 10px !important; }

/* ─── Header banner ─── */
.app-header {
    text-align: center;
    padding: 2rem 0 1.5rem;
    margin-bottom: 1rem;
}
.app-title {
    font-size: 3rem;
    font-weight: 800;
    background: linear-gradient(135deg, #60a5fa 0%, #a78bfa 50%, #f472b6 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    letter-spacing: -0.02em;
}
.app-subtitle {
    color: #64748b;
    font-size: 1rem;
    margin-top: 0.25rem;
}
</style>
""", unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════════
# 3. CONSTANTS ET CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

SERVICE_ICONS = {
    "virustotal":     ("🦠", "VirusTotal"),
    "abuseipdb":      ("🚨", "AbuseIPDB"),
    "greynoise":      ("📡", "GreyNoise"),
    "shodan":         ("🔭", "Shodan"),
    "alienvault":     ("👁️",  "AlienVault OTX"),
    "censys":         ("🗺️",  "Censys"),
    "securitytrails": ("🔍", "SecurityTrails"),
    "leakix":         ("💧", "LeakIX"),
    "hetrixtools":    ("📋", "HetrixTools"),
}

RISK_COLORS = {
    "CRITIQUE": "#ef4444",
    "ÉLEVÉ":    "#f97316",
    "MOYEN":    "#eab308",
    "FAIBLE":   "#22c55e",
}

HISTORY_FILE = "/mnt/agents/output/thk_history.json"


# ═══════════════════════════════════════════════════════════════════════════════
# 4. FONCTIONS UTILITAIRES
# ═══════════════════════════════════════════════════════════════════════════════

def load_api_keys() -> dict:
    """Charge les clés API depuis Streamlit Secrets."""
    keys = {}
    mapping = {
        "virustotal":     "VIRUSTOTAL_API_KEY",
        "abuseipdb":      "ABUSEIPDB_API_KEY",
        "shodan":         "SHODAN_API_KEY",
        "greynoise":      "GREYNOISE_API_KEY",
        "alienvault":     "ALIENVAULT_API_KEY",
        "censys":         "CENSYS_API_KEY",
        "securitytrails": "SECURITYTRAILS_KEY",
        "leakix":         "LEAKIX_API_KEY",
        "hetrixtools":    "HETRIXTOOLS_API_KEY",
    }
    for service, secret_name in mapping.items():
        try:
            keys[service] = st.secrets[secret_name]
        except KeyError:
            keys[service] = ""
    return keys


def _save_history_to_disk(history_list):
    """Sauvegarde l'historique sur disque pour persistance entre sessions."""
    try:
        serializable = []
        for item in history_list:
            d = asdict(item)
            serializable.append(d)
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(serializable, f, ensure_ascii=False, indent=2)
    except Exception as e:
        st.toast(f"⚠️ Impossible de sauvegarder l'historique: {e}", icon="⚠️")


def _load_history_from_disk():
    """Charge l'historique depuis le disque."""
    if not os.path.exists(HISTORY_FILE):
        return []
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        # Reconstruire les objets AnalysisResult si possible, sinon retourner les dicts
        return data
    except Exception:
        return []


def _render_service_card_native(svc_key, icon, svc_name, svc, status, target_type):
    """
    CORRECTION: Rendu natif Streamlit au lieu de HTML brut.
    Utilise les composants Streamlit natifs pour éviter les problèmes
    de rendu HTML dans les colonnes.
    """
    status_labels = {
        "success": ("● OK", "#22c55e"),
        "error":   ("● Erreur", "#ef4444"),
        "timeout": ("● Timeout", "#f97316"),
        "no_key":  ("● Pas de clé", "#64748b"),
    }
    status_label, status_color = status_labels.get(status, ("● —", "#64748b"))

    with st.container(border=True):
        # Titre du service
        cols_title = st.columns([0.1, 0.7, 0.2])
        with cols_title[0]:
            st.markdown(f"<span style='font-size:1.2rem'>{icon}</span>", unsafe_allow_html=True)
        with cols_title[1]:
            st.markdown(f"**{svc_name}**")
        with cols_title[2]:
            st.markdown(f"<span style='color:{status_color};font-size:0.7rem'>{status_label}</span>", unsafe_allow_html=True)

        if status == "success":
            if svc_key == "virustotal":
                mal = svc.get("malicious", 0)
                susp = svc.get("suspicious", 0)
                harm = svc.get("harmless", 0)
                und = svc.get("undetected", 0)
                total = svc.get("total", 1) or 1
                pct = lambda n: round(n / total * 100)

                c1, c2 = st.columns(2)
                with c1:
                    st.metric("Malveillant", mal, delta=None)
                    st.metric("Suspect", susp, delta=None)
                with c2:
                    st.metric("Total moteurs", total, delta=None)
                    st.metric("Réputation", svc.get("reputation", "N/A"), delta=None)

                # Barre de progression VT
                st.progress(mal / total, text=f"{mal} malveillant(s) sur {total}")

            elif svc_key == "abuseipdb":
                conf = svc.get("abuse_confidence", 0)
                reports = svc.get("total_reports", 0)
                col = "#ef4444" if conf > 50 else "#f97316" if conf > 20 else "#22c55e"

                c1, c2 = st.columns(2)
                with c1:
                    st.markdown(f"**Confiance abus:** <span style='color:{col};font-weight:700'>{conf}%</span>", unsafe_allow_html=True)
                    st.markdown(f"**Signalements:** {reports}")
                with c2:
                    st.markdown(f"**Pays:** {svc.get('country','N/A')}")
                    st.markdown(f"**ISP:** {str(svc.get('isp','N/A'))[:28]}")

            elif svc_key == "greynoise":
                noise = svc.get("noise", False)
                riot = svc.get("riot", False)
                clf = svc.get("classification", "N/A")
                clf_col = "#ef4444" if clf == "malicious" else "#22c55e" if clf == "benign" else "#64748b"

                c1, c2 = st.columns(2)
                with c1:
                    st.markdown(f"**Classification:** <span style='color:{clf_col}'>{clf}</span>", unsafe_allow_html=True)
                    st.markdown(f"**Noise:** {'Oui' if noise else 'Non'}")
                with c2:
                    st.markdown(f"**RIOT:** {'Oui' if riot else 'Non'}")
                    st.markdown(f"**Nom:** {str(svc.get('name','N/A'))[:24]}")

            elif svc_key == "shodan":
                ports = svc.get("ports", [])
                vulns = svc.get("vulns", [])
                tags = svc.get("tags", [])
                subs = svc.get("subdomains", [])

                if target_type == "ip":
                    ports_str = ", ".join(str(p) for p in ports[:6]) or "Aucun"
                    st.markdown(f"**Ports ouverts:** `{ports_str}`")
                    st.markdown(f"**CVE détectés:** <span style='color:{"#ef4444" if vulns else "#22c55e"}'>{len(vulns)}</span>", unsafe_allow_html=True)
                    st.markdown(f"**OS:** {svc.get('os','N/A') or 'N/A'}")
                    if vulns:
                        st.markdown("".join(f'<span class="tag-pill tag-orange">{v}</span>' for v in vulns[:4]), unsafe_allow_html=True)
                else:
                    st.markdown(f"**Sous-domaines:** {len(subs)}")

            elif svc_key == "alienvault":
                pulses = svc.get("pulse_count", 0)
                tags = svc.get("tags", [])
                col = "#ef4444" if pulses > 20 else "#f97316" if pulses > 5 else "#22c55e"
                st.markdown(f"**Pulses OTX:** <span style='color:{col};font-weight:700'>{pulses}</span>", unsafe_allow_html=True)
                if tags:
                    st.markdown("".join(f'<span class="tag-pill">{t[:20]}</span>' for t in tags[:5]), unsafe_allow_html=True)

            elif svc_key == "censys":
                services = svc.get("services", [])
                svcs_str = ", ".join(f"{s.get('port')}/{s.get('name','?')}" for s in services[:4]) or "N/A"
                c1, c2 = st.columns(2)
                with c1:
                    st.markdown(f"**Services exposés:** {len(services)}")
                    st.markdown(f"**OS:** {svc.get('os','N/A')}")
                with c2:
                    st.markdown(f"**Détail:** `{svcs_str}`")
                    st.markdown(f"**Pays:** {svc.get('country','N/A')}")

            elif svc_key == "securitytrails":
                if target_type == "domain":
                    a_recs = ", ".join(svc.get("a_records", [])[:3]) or "N/A"
                    st.markdown(f"**Sous-domaines:** {svc.get('subdomains',0)}")
                    st.markdown(f"**Enregistrements A:** `{a_recs}`")
                else:
                    st.markdown(f"**Domaines hébergés:** {svc.get('domains_hosted',0)}")

            elif svc_key == "leakix":
                leaks = svc.get("leaks", 0)
                leak_col = "#ef4444" if leaks > 0 else "#22c55e"
                c1, c2 = st.columns(2)
                with c1:
                    st.markdown(f"**Services trouvés:** {svc.get('services_found',0)}")
                with c2:
                    st.markdown(f"**Fuites détectées:** <span style='color:{leak_col};font-weight:700'>{leaks}</span>", unsafe_allow_html=True)

            elif svc_key == "hetrixtools":
                if target_type == "ip":
                    bl = svc.get("blacklisted_count", 0)
                    total = svc.get("total_checked", 0)
                    bl_col = "#ef4444" if bl > 5 else "#f97316" if bl > 0 else "#22c55e"
                    st.markdown(f"**Blacklisté sur:** <span style='color:{bl_col};font-weight:700'>{bl} / {total} RBLs</span>", unsafe_allow_html=True)
                    bls = svc.get("blacklists", [])
                    if bls:
                        st.markdown("".join(f'<span class="tag-pill tag-red">{b[:20]}</span>' for b in bls[:4]), unsafe_allow_html=True)
                else:
                    spf = svc.get("spf", "N/A")
                    dmarc = svc.get("dmarc", "N/A")
                    bl_count = svc.get("blacklist_count", 0)
                    st.markdown(f"**Blacklists:** {bl_count}")
                    st.markdown(f"**SPF:** `{str(spf)[:30]}`")
                    st.markdown(f"**DMARC:** `{str(dmarc)[:30]}`")
        else:
            reason = svc.get("reason") or svc.get("code") or "Service non disponible"
            st.info(reason)


def _render_result_card(result: AnalysisResult):
    """CORRECTION: Rendu natif Streamlit pour la carte de résultat principale."""
    level = result.risk_level
    score = result.risk_score
    color = RISK_COLORS.get(level, "#64748b")
    type_class = "type-ip" if result.target_type == "ip" else "type-domain"
    type_label = "IPv4" if result.target_type == "ip" else "Domaine"

    with st.container(border=True):
        # Header de la carte
        cols = st.columns([3, 1])
        with cols[0]:
            st.markdown(f"""
            <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.5rem">
                <span style="font-size:1.4rem;font-weight:700;color:#e2e8f0;font-family:'JetBrains Mono',monospace">{result.target}</span>
                <span class="target-type-badge {type_class}">{type_label}</span>
            </div>
            <div style="color:#64748b;font-size:0.85rem">{result.summary}</div>
            """, unsafe_allow_html=True)
        with cols[1]:
            st.markdown(f"""
            <div style="display:flex;align-items:center;justify-content:flex-end;gap:1rem">
                <div class="score-circle score-{level}" style="margin-left:auto">
                    <div style="font-size:1.3rem">{score}</div>
                    <div style="font-size:0.55rem;opacity:0.7">/100</div>
                </div>
                <span class="risk-badge risk-{level}">{level}</span>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("---")

        # Service detail columns — CORRECTION: utilisation de st.columns avec rendu natif
        svc_cols = st.columns(3)
        col_idx = 0

        for svc_key, (icon, svc_name) in SERVICE_ICONS.items():
            svc = result.services.get(svc_key, {})
            status = svc.get("status", "unknown")

            if status == "skipped":
                continue

            with svc_cols[col_idx % 3]:
                _render_service_card_native(svc_key, icon, svc_name, svc, status, result.target_type)

            col_idx += 1

        # Factors
        if result.factors:
            with st.expander("🔎 Facteurs de risque détaillés"):
                for f in result.factors:
                    st.markdown(f"- {f}")


# ═══════════════════════════════════════════════════════════════════════════════
# 5. INITIALISATION DU SESSION STATE (AVEC PERSISTANCE DISQUE)
# ═══════════════════════════════════════════════════════════════════════════════

if "results" not in st.session_state:
    st.session_state.results = []
if "history" not in st.session_state:
    # CORRECTION: Charger l'historique depuis le disque au démarrage
    disk_history = _load_history_from_disk()
    st.session_state.history = disk_history


# ═══════════════════════════════════════════════════════════════════════════════
# 6. SIDEBAR
# ═══════════════════════════════════════════════════════════════════════════════

with st.sidebar:
    st.markdown("## 🛡️ THK")
    st.markdown("<p style='color:#64748b;font-size:0.85rem;margin-top:-0.5rem;margin-bottom:1.5rem'>Threat Intelligence Hub</p>", unsafe_allow_html=True)

    st.markdown("### 🔑 Clés API")
    st.markdown("<p style='color:#64748b;font-size:0.8rem'>Renseignez les clés des services que vous souhaitez interroger. Les non renseignées seront ignorées.</p>", unsafe_allow_html=True)

    api_keys = load_api_keys()

    configured = sum(1 for v in api_keys.values() if v.strip())
    color = "#22c55e" if configured > 4 else "#eab308" if configured > 1 else "#ef4444"
    st.markdown(f"""
    <div style='margin-top:1rem;padding:0.75rem;background:rgba(0,0,0,0.3);border-radius:10px;border:1px solid rgba(255,255,255,0.06)'>
        <span style='color:{color};font-weight:700;font-size:0.9rem'>●</span>
        <span style='color:#94a3b8;font-size:0.85rem'> {configured}/9 services configurés</span>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("### ℹ️ À propos")
    st.markdown("""
    <p style='color:#64748b;font-size:0.8rem;line-height:1.6'>
    THK interroge en parallèle jusqu'à 9 sources de threat intelligence et calcule un score de risque agrégé (0–100).<br><br>
    <strong style='color:#94a3b8'>Compatible :</strong> IPs et domaines<br>
    <strong style='color:#94a3b8'>Analyse batch :</strong> plusieurs cibles à la fois
    </p>
    """, unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════════
# 7. HEADER PRINCIPAL
# ═══════════════════════════════════════════════════════════════════════════════

st.markdown("""
<div class="app-header">
    <div class="app-title">🛡️ THK</div>
    <div class="app-subtitle">Threat Intelligence Hub — Analyse multi-sources en temps réel</div>
</div>
""", unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════════
# 8. TABS — DÉCLARATION ET REMPLISSAGE DANS L'ORDRE LOGIQUE
# ═══════════════════════════════════════════════════════════════════════════════

tab_analyze, tab_history, tab_export = st.tabs(["🔍 Analyse", "📜 Historique", "📤 Export"])


# ── TAB 1 — Analyse ───────────────────────────────────────────────────────────

with tab_analyze:
    col_input, col_info = st.columns([2, 1])

    with col_input:
        st.markdown("#### Cibles à analyser")
        targets_input = st.text_area(
            label="Entrez vos IPs ou domaines",
            placeholder="8.8.8.8\n1.1.1.1\nexample.com\nmalware.xyz",
            height=140,
            label_visibility="collapsed",
        )

    with col_info:
        st.markdown("#### Conseils")
        st.markdown("""
        <div style='color:#64748b;font-size:0.85rem;line-height:1.8;background:rgba(0,0,0,0.2);padding:1rem;border-radius:10px;border:1px solid rgba(255,255,255,0.06)'>
        • Une cible par ligne<br>
        • IPv4, IPv6 ou domaine<br>
        • Jusqu'à 50 cibles par session<br>
        • Les services sans clé sont ignorés
        </div>
        """, unsafe_allow_html=True)

    col_btn, col_clear = st.columns([1, 4])
    with col_btn:
        run_btn = st.button("🚀 Analyser", use_container_width=True)
    with col_clear:
        if st.button("🗑️ Effacer les résultats", use_container_width=False):
            st.session_state.results = []
            st.rerun()

    if run_btn:
        targets = [t.strip() for t in targets_input.strip().splitlines() if t.strip()]

        if not targets:
            st.warning("⚠️ Veuillez entrer au moins une cible.")
        elif not any(v.strip() for v in api_keys.values()):
            st.error("❌ Aucune clé API configurée. Renseignez-en au moins une dans le panneau latéral.")
        else:
            clean_keys = {k: v.strip() for k, v in api_keys.items() if v.strip()}

            with st.spinner(f"🔍 Analyse de {len(targets)} cible(s) en cours..."):
                try:
                    results = run_analysis(targets, clean_keys)
                    st.session_state.results = results
                    st.session_state.history.extend(results)
                    # CORRECTION: Sauvegarder l'historique sur disque
                    _save_history_to_disk(st.session_state.history)
                    st.success(f"✅ Analyse terminée — {len(results)} cible(s) traitée(s)")
                except Exception as e:
                    st.error(f"❌ Erreur lors de l'analyse : {e}")

    # ── Results display ────────────────────────────────────────────────────────

    if st.session_state.results:
        results = st.session_state.results

        # Global summary strip
        scores = [r.risk_score for r in results]
        critiques = sum(1 for r in results if r.risk_level == "CRITIQUE")
        eleves    = sum(1 for r in results if r.risk_level == "ÉLEVÉ")
        moyens    = sum(1 for r in results if r.risk_level == "MOYEN")
        faibles   = sum(1 for r in results if r.risk_level == "FAIBLE")
        avg_score = int(sum(scores) / len(scores)) if scores else 0

        st.markdown("---")
        st.markdown("#### 📊 Résumé de la session")

        cols = st.columns(5)
        cards = [
            (str(len(results)), "Cibles analysées"),
            (str(avg_score) + "/100", "Score moyen"),
            (str(critiques), "🔴 Critiques"),
            (str(eleves), "🟠 Élevés"),
            (str(faibles), "🟢 Faibles"),
        ]
        for col, (val, label) in zip(cols, cards):
            with col:
                st.markdown(f"""
                <div class="metric-card">
                    <div class="metric-value">{val}</div>
                    <div class="metric-label">{label}</div>
                </div>
                """, unsafe_allow_html=True)

        st.markdown("---")

        # Per-target cards
        for result in results:
            _render_result_card(result)


# ── TAB 2 — History ───────────────────────────────────────────────────────────

with tab_history:
    # CORRECTION: Afficher TOUS les résultats de l'historique, pas seulement la session actuelle
    all_history = st.session_state.history

    if not all_history:
        st.info("Aucune analyse dans l'historique. Lancez une analyse dans l'onglet **Analyse**.")
    else:
        rows = []
        for r in all_history:
            # Gérer à la fois les objets AnalysisResult et les dicts JSON
            if isinstance(r, dict):
                rows.append({
                    "Cible": r.get("target", "N/A"),
                    "Type": r.get("target_type", "N/A").upper(),
                    "Score": r.get("risk_score", 0),
                    "Niveau": r.get("risk_level", "N/A"),
                    "Résumé": r.get("summary", ""),
                    "Date": r.get("timestamp", "")[:19].replace("T", " "),
                })
            else:
                rows.append({
                    "Cible": r.target,
                    "Type": r.target_type.upper(),
                    "Score": r.risk_score,
                    "Niveau": r.risk_level,
                    "Résumé": r.summary,
                    "Date": r.timestamp[:19].replace("T", " "),
                })
        df = pd.DataFrame(rows)

        st.dataframe(
            df,
            use_container_width=True,
            column_config={
                "Score": st.column_config.ProgressColumn("Score", min_value=0, max_value=100, format="%d"),
                "Niveau": st.column_config.TextColumn("Niveau"),
            },
            hide_index=True,
        )

        col_clear_h, col_export_h = st.columns([1, 4])
        with col_clear_h:
            if st.button("🗑️ Vider l'historique", key="clear_history_btn"):
                st.session_state.history = []
                if os.path.exists(HISTORY_FILE):
                    os.remove(HISTORY_FILE)
                st.rerun()
        with col_export_h:
            # CORRECTION: Bouton d'export direct depuis l'historique
            if all_history:
                hist_rows = []
                for r in all_history:
                    if isinstance(r, dict):
                        hist_rows.append(r)
                    else:
                        hist_rows.append(asdict(r))
                hist_json = json.dumps(hist_rows, ensure_ascii=False, indent=2)
                st.download_button(
                    "📥 Exporter l'historique JSON",
                    data=hist_json,
                    file_name=f"thk_history_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json",
                )


# ── TAB 3 — Export ────────────────────────────────────────────────────────────

with tab_export:
    # CORRECTION: L'export doit proposer les résultats de la session ET l'historique complet
    export_source = st.radio(
        "Source des données à exporter:",
        ["Résultats de la session actuelle", "Historique complet (toutes les sessions)"],
        horizontal=True,
    )

    if export_source == "Résultats de la session actuelle":
        source_data = st.session_state.results
    else:
        source_data = st.session_state.history

    if not source_data:
        st.info("Aucun résultat à exporter. Lancez d'abord une analyse.")
    else:
        st.markdown("#### Formats d'export disponibles")
        col_j, col_c = st.columns(2)

        # Normaliser les données (objets ou dicts)
        normalized = []
        for r in source_data:
            if isinstance(r, dict):
                normalized.append(r)
            else:
                normalized.append(asdict(r))

        with col_j:
            st.markdown("**JSON complet**")
            json_str = json.dumps(normalized, ensure_ascii=False, indent=2)
            st.download_button(
                "📥 Télécharger JSON",
                data=json_str,
                file_name=f"thk_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                use_container_width=True,
            )
            st.code(json_str[:600] + "\n...", language="json")

        with col_c:
            st.markdown("**CSV synthétique**")
            rows = []
            for r in normalized:
                rows.append({
                    "target": r.get("target", "N/A"),
                    "type": r.get("target_type", "N/A"),
                    "risk_score": r.get("risk_score", 0),
                    "risk_level": r.get("risk_level", "N/A"),
                    "vt_malicious": r.get("services", {}).get("virustotal", {}).get("malicious", "N/A"),
                    "vt_total": r.get("services", {}).get("virustotal", {}).get("total", "N/A"),
                    "abuseipdb_confidence": r.get("services", {}).get("abuseipdb", {}).get("abuse_confidence", "N/A"),
                    "abuseipdb_reports": r.get("services", {}).get("abuseipdb", {}).get("total_reports", "N/A"),
                    "alienvault_pulses": r.get("services", {}).get("alienvault", {}).get("pulse_count", "N/A"),
                    "greynoise_class": r.get("services", {}).get("greynoise", {}).get("classification", "N/A"),
                    "shodan_vulns": len(r.get("services", {}).get("shodan", {}).get("vulns", [])),
                    "factors": " | ".join(r.get("factors", [])),
                    "timestamp": r.get("timestamp", ""),
                })
            df = pd.DataFrame(rows)
            csv_str = df.to_csv(index=False)
            st.download_button(
                "📥 Télécharger CSV",
                data=csv_str,
                file_name=f"thk_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                use_container_width=True,
            )
            st.dataframe(df, use_container_width=True, hide_index=True)

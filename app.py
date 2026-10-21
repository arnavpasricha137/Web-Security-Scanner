"""
Web Security Scanner — Streamlit Dashboard
Run with:  streamlit run app.py
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime

from scanner.scanner import scan, ScanResult
from scanner.headers import HeaderFinding
from scanner.cors import CORSFinding

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="Web Security Scanner",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Theme constants
# ---------------------------------------------------------------------------

COLOR_PASS   = "#22c55e"
COLOR_WARN   = "#f59e0b"
COLOR_FAIL   = "#ef4444"
COLOR_CRIT   = "#dc2626"
COLOR_INFO   = "#6b7280"
COLOR_ACCENT = "#3b82f6"

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

STATUS_COLOR = {"PASS": COLOR_PASS, "WARN": COLOR_WARN, "FAIL": COLOR_FAIL, "INFO": COLOR_INFO}
SEVERITY_COLOR = {
    "CRITICAL": COLOR_CRIT,
    "HIGH":     COLOR_FAIL,
    "MEDIUM":   COLOR_WARN,
    "LOW":      "#3b82f6",
    "INFO":     COLOR_INFO,
}


# ---------------------------------------------------------------------------
# Custom CSS
# ---------------------------------------------------------------------------

st.markdown(
    """
<style>
/* ── global ─────────────────────────────── */
[data-testid="stAppViewContainer"] { background: #0f172a; color: #e2e8f0; }
[data-testid="stSidebar"]          { background: #1e293b; }
[data-testid="stHeader"]           { background: transparent; }

/* ── metric cards ────────────────────────── */
.metric-card {
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 12px;
    padding: 20px 24px;
    text-align: center;
}
.metric-label { font-size: 13px; color: #94a3b8; text-transform: uppercase; letter-spacing: .06em; margin-bottom: 6px; }
.metric-value { font-size: 38px; font-weight: 700; line-height: 1; }
.metric-sub   { font-size: 12px; color: #64748b; margin-top: 4px; }

/* ── badge ───────────────────────────────── */
.badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 999px;
    font-size: 12px;
    font-weight: 600;
    letter-spacing: .04em;
}

/* ── section title ──────────────────────── */
.section-title {
    font-size: 18px;
    font-weight: 700;
    color: #f1f5f9;
    border-left: 4px solid #3b82f6;
    padding-left: 12px;
    margin-bottom: 16px;
    margin-top: 24px;
}

/* ── finding card ────────────────────────── */
.finding-card {
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 10px;
    padding: 16px 20px;
    margin-bottom: 10px;
}
.finding-card.fail  { border-left: 4px solid #ef4444; }
.finding-card.warn  { border-left: 4px solid #f59e0b; }
.finding-card.pass  { border-left: 4px solid #22c55e; }
.finding-card.info  { border-left: 4px solid #6b7280; }
.finding-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
.finding-name   { font-size: 15px; font-weight: 600; color: #f1f5f9; }
.finding-value  { font-size: 12px; color: #94a3b8; font-family: monospace; margin-top: 4px; word-break: break-all; }
.finding-desc   { font-size: 13px; color: #cbd5e1; margin-top: 6px; }
.finding-rec    { font-size: 12px; color: #60a5fa; margin-top: 6px; font-style: italic; }
.finding-notes  { font-size: 12px; color: #fbbf24; margin-top: 6px; }

/* ── tls block ───────────────────────────── */
.tls-block {
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 10px;
    padding: 16px 20px;
}
.tls-row { display: flex; justify-content: space-between; border-bottom: 1px solid #1e3a5f; padding: 6px 0; font-size: 13px; }
.tls-row:last-child { border-bottom: none; }
.tls-key { color: #94a3b8; }
.tls-val { color: #e2e8f0; font-family: monospace; }

/* ── score ring label ────────────────────── */
.score-grade { font-size: 42px; font-weight: 800; text-align: center; }

/* ── tabs ─────────────────────────────────── */
button[data-baseweb="tab"] { font-size: 14px !important; }
</style>
""",
    unsafe_allow_html=True,
)


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def badge(text: str, color: str) -> str:
    return f'<span class="badge" style="background:{color}22;color:{color};border:1px solid {color}55">{text}</span>'


def score_color(score: int) -> str:
    if score >= 80:
        return COLOR_PASS
    if score >= 50:
        return COLOR_WARN
    return COLOR_FAIL


def score_grade(score: int) -> str:
    if score >= 90: return "A"
    if score >= 80: return "B"
    if score >= 65: return "C"
    if score >= 50: return "D"
    return "F"


def gauge_chart(score: int, title: str) -> go.Figure:
    color = score_color(score)
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        title={"text": title, "font": {"color": "#94a3b8", "size": 14}},
        number={"font": {"color": color, "size": 36}, "suffix": "/100"},
        gauge={
            "axis": {"range": [0, 100], "tickcolor": "#334155", "tickfont": {"color": "#64748b"}},
            "bar": {"color": color, "thickness": 0.25},
            "bgcolor": "#1e293b",
            "bordercolor": "#334155",
            "steps": [
                {"range": [0,  50], "color": "#1e1a2e"},
                {"range": [50, 80], "color": "#1a2535"},
                {"range": [80,100], "color": "#0f2a1f"},
            ],
            "threshold": {
                "line": {"color": color, "width": 3},
                "thickness": 0.75,
                "value": score,
            },
        },
    ))
    fig.update_layout(
        paper_bgcolor="#0f172a",
        plot_bgcolor="#0f172a",
        font_color="#e2e8f0",
        height=200,
        margin=dict(t=40, b=0, l=20, r=20),
    )
    return fig


def radar_chart(header_findings: list[HeaderFinding]) -> go.Figure:
    categories = [f.header.replace("-", "-<br>") for f in header_findings]
    scores = []
    for f in header_findings:
        if f.status == "PASS":   scores.append(100)
        elif f.status == "WARN": scores.append(50)
        else:                    scores.append(0)

    fig = go.Figure(go.Scatterpolar(
        r=scores + [scores[0]],
        theta=categories + [categories[0]],
        fill="toself",
        fillcolor="rgba(59,130,246,0.15)",
        line=dict(color=COLOR_ACCENT, width=2),
        marker=dict(color=COLOR_ACCENT, size=6),
    ))
    fig.update_layout(
        polar=dict(
            bgcolor="#1e293b",
            radialaxis=dict(visible=True, range=[0, 100], tickfont=dict(color="#64748b", size=10), gridcolor="#334155"),
            angularaxis=dict(tickfont=dict(color="#94a3b8", size=10), gridcolor="#334155"),
        ),
        paper_bgcolor="#0f172a",
        font_color="#e2e8f0",
        height=380,
        margin=dict(t=20, b=20, l=40, r=40),
        showlegend=False,
    )
    return fig


def waterfall_chart(header_findings: list[HeaderFinding]) -> go.Figure:
    colors = [STATUS_COLOR.get(f.status, COLOR_INFO) for f in header_findings]
    fig = go.Figure(go.Bar(
        x=[f.header for f in header_findings],
        y=[100 if f.status == "PASS" else 50 if f.status == "WARN" else 0 for f in header_findings],
        marker_color=colors,
        text=[f.status for f in header_findings],
        textposition="outside",
        textfont=dict(color="#e2e8f0", size=11),
    ))
    fig.update_layout(
        paper_bgcolor="#0f172a",
        plot_bgcolor="#0f172a",
        font_color="#e2e8f0",
        xaxis=dict(tickfont=dict(size=10), tickangle=-30, gridcolor="#1e293b"),
        yaxis=dict(range=[0, 130], gridcolor="#334155", tickvals=[0, 50, 100], ticktext=["FAIL", "WARN", "PASS"]),
        height=300,
        margin=dict(t=10, b=10, l=10, r=10),
    )
    return fig


def cors_severity_pie(cors_findings: list[CORSFinding]) -> go.Figure:
    fails = [f for f in cors_findings if f.status == "FAIL"]
    if not fails:
        fig = go.Figure()
        fig.update_layout(paper_bgcolor="#0f172a", plot_bgcolor="#0f172a",
                          annotations=[dict(text="No CORS Issues Found", x=0.5, y=0.5,
                                            font=dict(color=COLOR_PASS, size=16), showarrow=False)],
                          height=250, margin=dict(t=10, b=10))
        return fig

    counts: dict[str, int] = {}
    for f in fails:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    labels = list(counts.keys())
    values = list(counts.values())
    clrs = [SEVERITY_COLOR.get(s, COLOR_INFO) for s in labels]

    fig = go.Figure(go.Pie(
        labels=labels,
        values=values,
        marker=dict(colors=clrs, line=dict(color="#0f172a", width=2)),
        textfont=dict(color="#e2e8f0"),
        hole=0.5,
    ))
    fig.update_layout(
        paper_bgcolor="#0f172a",
        font_color="#e2e8f0",
        height=250,
        margin=dict(t=10, b=10, l=10, r=10),
        legend=dict(font=dict(color="#94a3b8")),
        showlegend=True,
    )
    return fig


# ---------------------------------------------------------------------------
# Render helpers
# ---------------------------------------------------------------------------

def render_header_card(f: HeaderFinding):
    css_class = f.status.lower()
    sev_color = SEVERITY_COLOR.get(f.severity, COLOR_INFO)
    sts_color = STATUS_COLOR.get(f.status, COLOR_INFO)

    notes_html = ""
    if f.notes:
        items = "".join(f"<li>{n}</li>" for n in f.notes)
        notes_html = f'<div class="finding-notes">⚠ Notes:<ul style="margin:4px 0 0 16px;padding:0">{items}</ul></div>'

    value_html = (
        f'<div class="finding-value">Value: <code style="color:#93c5fd">{f.value}</code></div>'
        if f.value else
        '<div class="finding-value" style="color:#ef4444">Header not present in response.</div>'
    )

    st.markdown(
        f"""
<div class="finding-card {css_class}">
  <div class="finding-header">
    <span class="finding-name">{f.header}</span>
    <span>
      {badge(f.severity, sev_color)}&nbsp;{badge(f.status, sts_color)}
    </span>
  </div>
  <div class="finding-desc">{f.description}</div>
  {value_html}
  {notes_html}
  <div class="finding-rec">💡 {f.recommendation}</div>
</div>
""",
        unsafe_allow_html=True,
    )


def render_cors_card(f: CORSFinding):
    css_class = f.status.lower()
    sev_color = SEVERITY_COLOR.get(f.severity, COLOR_INFO)
    sts_color = STATUS_COLOR.get(f.status, COLOR_INFO)

    acao_html = (
        f'<div class="finding-value">ACAO: <code style="color:#f87171">{f.acao_header}</code></div>'
        if f.acao_header else
        '<div class="finding-value" style="color:#6b7280">ACAO header absent.</div>'
    )

    st.markdown(
        f"""
<div class="finding-card {css_class}">
  <div class="finding-header">
    <span class="finding-name">{f.test_name}</span>
    <span>
      {badge(f.severity, sev_color)}&nbsp;{badge(f.status, sts_color)}
    </span>
  </div>
  <div class="finding-desc" style="font-size:12px;color:#94a3b8">Origin sent: <code>{f.origin_sent}</code></div>
  {acao_html}
  <div class="finding-desc">{f.details}</div>
  <div class="finding-rec">💡 {f.recommendation}</div>
</div>
""",
        unsafe_allow_html=True,
    )


def render_tls_block(tls):
    if not tls.enabled:
        st.markdown(
            f'<div class="tls-block"><span style="color:{COLOR_FAIL}">⚠ TLS could not be verified: {tls.error}</span></div>',
            unsafe_allow_html=True,
        )
        return

    expiry_color = COLOR_PASS
    if tls.days_until_expiry is not None:
        if tls.days_until_expiry < 14:
            expiry_color = COLOR_FAIL
        elif tls.days_until_expiry < 30:
            expiry_color = COLOR_WARN

    rows = [
        ("Protocol",         tls.version or "—"),
        ("Cipher Suite",     tls.cipher or "—"),
        ("Certificate CN",   tls.cert_subject or "—"),
        ("Expires",          tls.cert_expiry or "—"),
        ("Days Until Expiry",
         f'<span style="color:{expiry_color}">{tls.days_until_expiry if tls.days_until_expiry is not None else "—"}</span>'),
    ]

    rows_html = "".join(
        f'<div class="tls-row"><span class="tls-key">{k}</span><span class="tls-val">{v}</span></div>'
        for k, v in rows
    )
    st.markdown(f'<div class="tls-block">{rows_html}</div>', unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Sidebar & state
# ---------------------------------------------------------------------------

with st.sidebar:
    st.markdown(
        '<div style="font-size:22px;font-weight:800;color:#f1f5f9;margin-bottom:4px">🔒 WebSecScan</div>'
        '<div style="font-size:12px;color:#64748b;margin-bottom:24px">Headers · CORS · TLS Auditor</div>',
        unsafe_allow_html=True,
    )

    target_url = st.text_input(
        "Target URL",
        placeholder="https://example.com",
        help="Full URL including scheme (https://)",
    )

    with st.expander("⚙ Scan Options", expanded=False):
        scan_cors_flag = st.checkbox("Enable CORS Probes", value=True)
        timeout_val = st.slider("Timeout (seconds)", 5, 30, 10)

    scan_btn = st.button("🚀 Run Scan", use_container_width=True, type="primary")

    st.markdown("---")
    st.markdown(
        """
<div style="font-size:12px;color:#475569">
<b>What is checked?</b><br><br>
• 8 security response headers<br>
• Server info leakage headers<br>
• 7 CORS misconfiguration probes<br>
• TLS version & certificate validity<br>
• HTTP → HTTPS redirect chain
</div>
""",
        unsafe_allow_html=True,
    )

    # History
    if "history" not in st.session_state:
        st.session_state.history = []

    if st.session_state.history:
        st.markdown("---")
        st.markdown('<div style="font-size:12px;color:#64748b;margin-bottom:8px">Recent Scans</div>', unsafe_allow_html=True)
        for item in reversed(st.session_state.history[-5:]):
            col1, col2 = st.columns([3, 1])
            col1.markdown(f'<div style="font-size:11px;color:#94a3b8;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{item["url"]}</div>', unsafe_allow_html=True)
            col2.markdown(
                f'<div style="font-size:11px;font-weight:700;color:{score_color(item["score"])}">{item["score"]}</div>',
                unsafe_allow_html=True,
            )


# ---------------------------------------------------------------------------
# Main content
# ---------------------------------------------------------------------------

st.markdown(
    """
<div style="text-align:center;padding:32px 0 8px 0">
  <div style="font-size:32px;font-weight:800;color:#f1f5f9">Web Security Scanner</div>
  <div style="font-size:15px;color:#64748b;margin-top:6px">
    Audit HTTP security headers, detect CORS misconfigurations, and inspect TLS.
  </div>
</div>
""",
    unsafe_allow_html=True,
)

# ── Landing state ────────────────────────────────────────────────────────────
if not scan_btn:
    st.markdown(
        """
<div style="max-width:600px;margin:40px auto;background:#1e293b;border:1px solid #334155;
            border-radius:14px;padding:28px 32px">
  <div style="font-size:16px;font-weight:700;color:#f1f5f9;margin-bottom:16px">🛡️ What this tool checks</div>
  <table style="width:100%;border-collapse:collapse;font-size:13px;color:#cbd5e1">
    <tr><th style="text-align:left;padding:6px 0;color:#64748b;font-weight:600">Category</th>
        <th style="text-align:left;padding:6px 0;color:#64748b;font-weight:600">Details</th></tr>
    <tr style="border-top:1px solid #334155">
      <td style="padding:8px 0"><b>Security Headers</b></td>
      <td>HSTS · CSP · X-Frame-Options · X-Content-Type-Options · Referrer-Policy · Permissions-Policy · X-XSS-Protection · Cache-Control</td>
    </tr>
    <tr style="border-top:1px solid #334155">
      <td style="padding:8px 0"><b>CORS Probes</b></td>
      <td>Wildcard origin · Arbitrary origin reflection · Credentialed requests · Null origin · HTTP origins</td>
    </tr>
    <tr style="border-top:1px solid #334155">
      <td style="padding:8px 0"><b>TLS / HTTPS</b></td>
      <td>Protocol version · Cipher suite · Certificate expiry · HTTP→HTTPS redirect</td>
    </tr>
    <tr style="border-top:1px solid #334155">
      <td style="padding:8px 0"><b>Info Leakage</b></td>
      <td>Server · X-Powered-By · X-AspNet-Version banners</td>
    </tr>
  </table>
  <div style="margin-top:20px;font-size:12px;color:#475569">
    Enter a URL in the sidebar and click <b>Run Scan</b> to begin.
  </div>
</div>
""",
        unsafe_allow_html=True,
    )
    st.stop()

# ── Validation ────────────────────────────────────────────────────────────────
if not target_url.strip():
    st.error("Please enter a target URL in the sidebar.")
    st.stop()

# ── Run scan ──────────────────────────────────────────────────────────────────
with st.spinner(f"Scanning **{target_url}** …"):
    result: ScanResult = scan(target_url.strip(), timeout=timeout_val, scan_cors=scan_cors_flag)

# Save history
st.session_state.history.append({"url": result.url, "score": result.overall_score})

if result.error:
    st.error(f"⚠ Scan encountered an error: {result.error}")

# ── Overview strip ────────────────────────────────────────────────────────────
st.markdown(
    f"""
<div style="display:flex;gap:12px;flex-wrap:wrap;margin:24px 0 8px 0">
  <div class="metric-card" style="flex:1;min-width:140px">
    <div class="metric-label">Overall Score</div>
    <div class="metric-value" style="color:{score_color(result.overall_score)}">{result.overall_score}</div>
    <div class="metric-sub">Grade: {score_grade(result.overall_score)}</div>
  </div>
  <div class="metric-card" style="flex:1;min-width:140px">
    <div class="metric-label">Header Score</div>
    <div class="metric-value" style="color:{score_color(result.header_score)}">{result.header_score}</div>
    <div class="metric-sub">out of 100</div>
  </div>
  <div class="metric-card" style="flex:1;min-width:140px">
    <div class="metric-label">CORS Score</div>
    <div class="metric-value" style="color:{score_color(result.cors_score_val)}">{result.cors_score_val}</div>
    <div class="metric-sub">out of 100</div>
  </div>
  <div class="metric-card" style="flex:1;min-width:140px">
    <div class="metric-label">HTTP Status</div>
    <div class="metric-value" style="color:{COLOR_PASS if result.status_code and result.status_code < 400 else COLOR_FAIL}">{result.status_code or "—"}</div>
    <div class="metric-sub">{round(result.elapsed_seconds,2)}s elapsed</div>
  </div>
  <div class="metric-card" style="flex:1;min-width:140px">
    <div class="metric-label">TLS</div>
    <div class="metric-value" style="color:{COLOR_PASS if result.tls.enabled else COLOR_FAIL}">{"✓" if result.tls.enabled else "✗"}</div>
    <div class="metric-sub">{result.tls.version or ("Disabled" if not result.tls.enabled else "")}</div>
  </div>
  <div class="metric-card" style="flex:1;min-width:140px">
    <div class="metric-label">HTTPS Redirect</div>
    <div class="metric-value" style="color:{COLOR_PASS if result.redirect.http_redirects_to_https else COLOR_WARN}">{"✓" if result.redirect.http_redirects_to_https else "✗"}</div>
    <div class="metric-sub">HTTP → HTTPS</div>
  </div>
</div>
""",
    unsafe_allow_html=True,
)

# ── Tabs ──────────────────────────────────────────────────────────────────────
tab_overview, tab_headers, tab_cors, tab_tls, tab_raw = st.tabs(
    ["📊 Overview", "🛡 Security Headers", "🌐 CORS Probes", "🔑 TLS / Redirect", "📋 Raw Data"]
)

# ═══════════════════════════════════════════════════════════════════════════════
# TAB 1 — OVERVIEW
# ═══════════════════════════════════════════════════════════════════════════════
with tab_overview:
    g1, g2, g3 = st.columns(3)
    with g1:
        st.plotly_chart(gauge_chart(result.overall_score, "Overall Score"), use_container_width=True, config={"displayModeBar": False})
    with g2:
        st.plotly_chart(gauge_chart(result.header_score,  "Header Score"),  use_container_width=True, config={"displayModeBar": False})
    with g3:
        st.plotly_chart(gauge_chart(result.cors_score_val, "CORS Score"),   use_container_width=True, config={"displayModeBar": False})

    st.markdown('<div class="section-title">Header Coverage Radar</div>', unsafe_allow_html=True)
    st.plotly_chart(radar_chart(result.header_findings), use_container_width=True, config={"displayModeBar": False})

    col_sum, col_pie = st.columns([2, 1])
    with col_sum:
        st.markdown('<div class="section-title">Summary Table</div>', unsafe_allow_html=True)

        fails   = [f for f in result.header_findings if f.status == "FAIL"]
        warns   = [f for f in result.header_findings if f.status == "WARN"]
        passes  = [f for f in result.header_findings if f.status == "PASS"]
        c_fails = [f for f in result.cors_findings if f.status == "FAIL"]

        df = pd.DataFrame({
            "Category": ["Security Headers", "Security Headers", "Security Headers", "CORS Probes"],
            "Status":   ["FAIL", "WARN", "PASS", "Misconfigured"],
            "Count":    [len(fails), len(warns), len(passes), len(c_fails)],
        })
        st.dataframe(
            df,
            hide_index=True,
            use_container_width=True,
            column_config={
                "Category": st.column_config.TextColumn("Category"),
                "Status":   st.column_config.TextColumn("Status"),
                "Count":    st.column_config.NumberColumn("Count"),
            },
        )

        if result.leaky_headers:
            st.markdown('<div class="section-title">⚠ Information Leakage</div>', unsafe_allow_html=True)
            for lh in result.leaky_headers:
                st.markdown(
                    f'<div class="finding-card warn"><div class="finding-header"><span class="finding-name">{lh.header}</span>{badge("INFO", COLOR_WARN)}</div>'
                    f'<div class="finding-value">Value: <code>{lh.value}</code></div>'
                    f'<div class="finding-rec">💡 {lh.note}</div></div>',
                    unsafe_allow_html=True,
                )

    with col_pie:
        st.markdown('<div class="section-title">CORS Issue Severity</div>', unsafe_allow_html=True)
        st.plotly_chart(cors_severity_pie(result.cors_findings), use_container_width=True, config={"displayModeBar": False})


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 2 — SECURITY HEADERS
# ═══════════════════════════════════════════════════════════════════════════════
with tab_headers:
    st.plotly_chart(waterfall_chart(result.header_findings), use_container_width=True, config={"displayModeBar": False})

    filter_col, sort_col = st.columns(2)
    with filter_col:
        status_filter = st.multiselect(
            "Filter by Status",
            ["PASS", "WARN", "FAIL"],
            default=["FAIL", "WARN", "PASS"],
        )
    with sort_col:
        sort_by = st.selectbox("Sort by", ["Severity (worst first)", "Status", "Header name"])

    filtered = [f for f in result.header_findings if f.status in status_filter]

    if sort_by == "Severity (worst first)":
        sev_rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        status_rank = {"FAIL": 0, "WARN": 1, "PASS": 2}
        filtered.sort(key=lambda x: (status_rank.get(x.status, 3), sev_rank.get(x.severity, 3)))
    elif sort_by == "Status":
        filtered.sort(key=lambda x: ["FAIL", "WARN", "PASS"].index(x.status) if x.status in ["FAIL","WARN","PASS"] else 99)
    else:
        filtered.sort(key=lambda x: x.header)

    for f in filtered:
        render_header_card(f)


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 3 — CORS PROBES
# ═══════════════════════════════════════════════════════════════════════════════
with tab_cors:
    if not scan_cors_flag:
        st.info("CORS probes were disabled. Enable them in the sidebar options.")
    elif not result.cors_findings:
        st.success("No CORS findings returned.")
    else:
        fails_only = st.checkbox("Show failed probes only", value=False)
        displayed = [f for f in result.cors_findings if f.status == "FAIL"] if fails_only else result.cors_findings
        # Sort: failures first
        displayed.sort(key=lambda x: (0 if x.status == "FAIL" else 1, SEVERITY_ORDER.get(x.severity, 99)))

        for f in displayed:
            render_cors_card(f)


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 4 — TLS / REDIRECT
# ═══════════════════════════════════════════════════════════════════════════════
with tab_tls:
    tls_col, redir_col = st.columns(2)

    with tls_col:
        st.markdown('<div class="section-title">TLS Certificate</div>', unsafe_allow_html=True)
        render_tls_block(result.tls)

        if result.tls.enabled and result.tls.days_until_expiry is not None:
            expiry_pct = min(100, max(0, result.tls.days_until_expiry / 365 * 100))
            bar_color = COLOR_PASS if result.tls.days_until_expiry > 30 else COLOR_WARN if result.tls.days_until_expiry > 14 else COLOR_FAIL
            st.markdown(
                f'<div style="margin-top:16px"><div style="font-size:12px;color:#94a3b8;margin-bottom:6px">Certificate validity remaining</div>'
                f'<div style="background:#1e293b;border-radius:999px;overflow:hidden;height:10px">'
                f'<div style="width:{expiry_pct:.0f}%;background:{bar_color};height:10px;border-radius:999px;transition:width .5s"></div>'
                f'</div><div style="font-size:11px;color:#64748b;margin-top:4px">{result.tls.days_until_expiry} days remaining</div></div>',
                unsafe_allow_html=True,
            )

    with redir_col:
        st.markdown('<div class="section-title">Redirect Chain</div>', unsafe_allow_html=True)
        if result.redirect.redirect_chain:
            chain_html = ""
            for i, url_step in enumerate(result.redirect.redirect_chain):
                arrow = "" if i == 0 else '<div style="color:#334155;padding:2px 0">↓</div>'
                color = COLOR_PASS if url_step.startswith("https") else COLOR_WARN
                chain_html += f'{arrow}<div style="font-size:12px;font-family:monospace;color:{color};background:#1e293b;padding:6px 10px;border-radius:6px;word-break:break-all">{url_step}</div>'
            st.markdown(f'<div>{chain_html}</div>', unsafe_allow_html=True)

            redirect_ok = result.redirect.http_redirects_to_https
            st.markdown(
                f'<div style="margin-top:12px;font-size:13px;color:{"#22c55e" if redirect_ok else "#f59e0b"}">'
                f'{"✓ HTTP correctly redirects to HTTPS." if redirect_ok else "⚠ HTTP does not redirect to HTTPS."}</div>',
                unsafe_allow_html=True,
            )
        else:
            st.markdown('<div style="color:#64748b;font-size:13px">No redirect chain captured.</div>', unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 5 — RAW DATA
# ═══════════════════════════════════════════════════════════════════════════════
with tab_raw:
    st.markdown('<div class="section-title">All Header Findings</div>', unsafe_allow_html=True)
    header_df = pd.DataFrame([
        {
            "Header":         f.header,
            "Present":        f.present,
            "Status":         f.status,
            "Severity":       f.severity,
            "Value":          f.value or "",
            "Notes":          "; ".join(f.notes),
        }
        for f in result.header_findings
    ])
    st.dataframe(header_df, hide_index=True, use_container_width=True)

    st.markdown('<div class="section-title">All CORS Findings</div>', unsafe_allow_html=True)
    cors_df = pd.DataFrame([
        {
            "Test":           f.test_name,
            "Origin Sent":    f.origin_sent,
            "Status":         f.status,
            "Severity":       f.severity,
            "ACAO":           f.acao_header or "",
            "ACAC":           f.acac_header or "",
            "Details":        f.details,
        }
        for f in result.cors_findings
    ])
    st.dataframe(cors_df, hide_index=True, use_container_width=True)

    st.markdown('<div class="section-title">Scan Metadata</div>', unsafe_allow_html=True)
    meta = {
        "URL":           result.url,
        "Final URL":     result.final_url or "—",
        "Scanned At":    result.scanned_at,
        "Elapsed (s)":   result.elapsed_seconds,
        "HTTP Status":   result.status_code,
        "Overall Score": result.overall_score,
        "Header Score":  result.header_score,
        "CORS Score":    result.cors_score_val,
    }
    st.json(meta)

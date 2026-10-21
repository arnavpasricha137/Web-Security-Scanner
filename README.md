# 🔒 Web Security Scanner

A professional Python + Streamlit dashboard that audits websites for HTTP security header misconfigurations, CORS flaws, TLS certificate health, and information leakage.

---

## Features

| Category | What is checked |
|---|---|
| **Security Headers** | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-XSS-Protection, Cache-Control |
| **CORS Probes** | Wildcard origin, arbitrary origin reflection, credentialed arbitrary origin (critical), null origin, HTTP origin acceptance |
| **TLS / HTTPS** | Protocol version, cipher suite, certificate CN, days until expiry, HTTP→HTTPS redirect chain |
| **Info Leakage** | Server, X-Powered-By, X-AspNet-Version banners |

## Scoring

- **Header Score** — weighted deduction per missing/misconfigured header (HIGH=30pts, MEDIUM=20pts, LOW=10pts)
- **CORS Score** — deduction per failed probe (CRITICAL=40pts, HIGH=25pts, MEDIUM=15pts)
- **Overall Score** — 55% headers + 45% CORS (0–100)

---

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Launch the dashboard
streamlit run app.py
```

Then open `http://localhost:8501` in your browser, enter a URL in the sidebar and click **Run Scan**.

---

## Project Structure

```
.
├── app.py                  # Streamlit dashboard
├── requirements.txt
├── .streamlit/
│   └── config.toml         # Dark theme config
└── scanner/
    ├── __init__.py
    ├── scanner.py           # Scan orchestrator (TLS, redirect, calls headers + CORS)
    ├── headers.py           # Security header definitions, validators, scorer
    └── cors.py              # CORS probe payloads, HTTP client, scorer
```

---

## Dashboard Tabs

| Tab | Contents |
|---|---|
| **Overview** | Score gauges, radar chart, summary table, leaky header callouts, CORS severity pie |
| **Security Headers** | Bar chart + filterable/sortable finding cards with value, notes, recommendations |
| **CORS Probes** | Per-probe finding cards with origin sent, ACAO value, severity, recommendation |
| **TLS / Redirect** | TLS metadata, certificate expiry progress bar, redirect chain visualisation |
| **Raw Data** | Exportable DataFrames for headers & CORS findings, JSON scan metadata |

---

## Disclaimer

> This tool is intended for **authorised security testing only**. Always obtain written permission before scanning any system you do not own.

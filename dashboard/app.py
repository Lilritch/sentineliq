"""
app.py — Streamlit real-time SIEM dashboard
Polls the FastAPI backend every few seconds and renders live charts.

Run with: streamlit run dashboard/app.py
"""

import time
import requests
import pandas as pd
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime

API_BASE = "http://127.0.0.1:8000"

st.set_page_config(
    page_title="SentinelIQ Dashboard",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ SentinelIQ SIEM Dashboard")
st.caption("Real-time security log monitoring with risk scoring and rule-based triage")

# ── Sidebar controls ────────────────────────────────────────────────────────
st.sidebar.header("Controls")
auto_refresh = st.sidebar.checkbox("Auto-refresh (every 3s)", value=True)
severity_filter = st.sidebar.selectbox(
    "Filter by severity",
    ["all", "critical", "high", "medium", "low", "info"],
)
alert_limit = st.sidebar.slider("Max alerts to show", 10, 200, 50)

if st.sidebar.button("🔴 Clear All Alerts"):
    requests.delete(f"{API_BASE}/alerts/clear")
    st.rerun()

if st.sidebar.button("⚡ Simulate 10 Live Logs"):
    for _ in range(10):
        requests.get(f"{API_BASE}/simulate")
    st.rerun()


# ── Fetch alerts ────────────────────────────────────────────────────────────
def fetch_alerts(severity: str = "all", limit: int = 50) -> list:
    try:
        params = {"limit": limit}
        if severity != "all":
            params["severity"] = severity
        r = requests.get(f"{API_BASE}/alerts", params=params, timeout=3)
        return r.json().get("alerts", [])
    except Exception:
        return []


def fetch_health() -> dict:
    try:
        return requests.get(f"{API_BASE}/", timeout=2).json()
    except Exception:
        return {}


# ── Main dashboard ──────────────────────────────────────────────────────────
health = fetch_health()
alerts = fetch_alerts(severity_filter, alert_limit)
df = pd.DataFrame(alerts) if alerts else pd.DataFrame()

# ── KPI row ─────────────────────────────────────────────────────────────────
col1, col2, col3, col4, col5 = st.columns(5)

total = len(df) if not df.empty else 0
critical = len(df[df["severity"] == "critical"]) if not df.empty else 0
high = len(df[df["severity"] == "high"]) if not df.empty else 0
medium = len(df[df["severity"] == "medium"]) if not df.empty else 0
model_ok = "✅ Loaded" if health.get("scoring_ready") else "❌ Not loaded"

col1.metric("Total Alerts", total)
col2.metric("🔴 Critical", critical)
col3.metric("🟠 High", high)
col4.metric("🟡 Medium", medium)
col5.metric("Scoring Engine", model_ok)

st.divider()

# ── Charts row ──────────────────────────────────────────────────────────────
if not df.empty:
    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:
        severity_counts = df["severity"].value_counts().reset_index()
        severity_counts.columns = ["severity", "count"]
        color_map = {
            "critical": "#e74c3c", "high": "#e67e22",
            "medium": "#f1c40f", "low": "#2ecc71", "info": "#95a5a6",
        }
        fig = px.pie(
            severity_counts, values="count", names="severity",
            title="Alert Distribution by Severity",
            color="severity", color_discrete_map=color_map,
        )
        st.plotly_chart(fig, use_container_width=True)

    with chart_col2:
        if "risk_score" in df.columns:
            fig2 = px.histogram(
                df, x="risk_score", nbins=30,
                title="Risk Score Distribution",
                labels={"risk_score": "Risk Score"},
                color_discrete_sequence=["#3498db"],
            )
            fig2.add_vline(x=0.6, line_dash="dash", line_color="red",
                           annotation_text="Alert threshold")
            st.plotly_chart(fig2, use_container_width=True)

    # ── MITRE ATT&CK tactics ────────────────────────────────────────────────
    if "mitre_tactics" in df.columns:
        all_tactics = [t for sublist in df["mitre_tactics"] for t in sublist]
        if all_tactics:
            tactic_df = pd.Series(all_tactics).value_counts().reset_index()
            tactic_df.columns = ["tactic", "count"]
            fig3 = px.bar(
                tactic_df, x="count", y="tactic", orientation="h",
                title="🎯 MITRE ATT&CK Tactics Detected",
                color="count", color_continuous_scale="Reds",
            )
            st.plotly_chart(fig3, use_container_width=True)

    # ── Alert table ─────────────────────────────────────────────────────────
    st.subheader("📋 Recent Alerts")
    display_cols = [
        "timestamp", "severity", "user", "source_ip",
        "event_type", "risk_score", "description",
    ]
    available = [c for c in display_cols if c in df.columns]

    def color_severity(val):
        colors = {
            "critical": "background-color: #e74c3c; color: white",
            "high": "background-color: #e67e22; color: white",
            "medium": "background-color: #f39c12; color: white",
            "low": "background-color: #2ecc71; color: white",
        }
        return colors.get(val, "")

    styled = df[available].style.map(color_severity, subset=["severity"])
    st.dataframe(styled, use_container_width=True, height=400)

else:
    st.info("No alerts yet. Click '⚡ Simulate 10 Live Logs' in the sidebar to generate data.")

# ── Auto-refresh ─────────────────────────────────────────────────────────────
if auto_refresh:
    time.sleep(3)
    st.rerun()

import streamlit as st
import json
import pandas as pd
from pathlib import Path

st.set_page_config(
    page_title="AI-Sentinel Audit Dashboard",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ AI-Sentinel Security & Telemetry Dashboard")
st.markdown("Real-time observability layer monitoring prompt inspections, risk scores, and threat triggers from `audit_ledger.jsonl`.")

LOG_PATH = Path("audit_ledger.jsonl")

def load_audit_logs():
    if not LOG_PATH.exists():
        return pd.DataFrame()
    records = []
    with open(LOG_PATH, "r", encoding="utf-8") as f:
        for line in f:
            try:
                records.append(json.loads(line.strip()))
            except Exception:
                pass
    if not records:
        return pd.DataFrame()
    return pd.DataFrame(records)

df = load_audit_logs()

if df.empty:
    st.warning("No audit logs found yet (`audit_ledger.jsonl` is empty or missing). Run some benchmark tests or API requests first!")
else:
    # Summary metrics
    total_requests = len(df)
    blocked_count = len(df[df["action"] == "BLOCK"]) if "action" in df.columns else 0
    flagged_count = len(df[df["action"] == "FLAG"]) if "action" in df.columns else 0
    allowed_count = len(df[df["action"] == "ALLOW"]) if "action" in df.columns else 0

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Requests", total_requests)
    col2.metric("Allowed", allowed_count)
    col3.metric("Flagged", flagged_count)
    col4.metric("Blocked", blocked_count)

    st.divider()

    # Visualizations
    col_a, col_b = st.columns(2)
    
    with col_a:
        st.subheader("Action Distribution")
        if "action" in df.columns:
            action_counts = df["action"].value_counts()
            st.bar_chart(action_counts)

    with col_b:
        st.subheader("Risk Score Trend")
        if "risk_score" in df.columns:
            st.line_chart(df["risk_score"])

    st.divider()
    st.subheader("📋 Detailed Audit Ledger Records")
    st.dataframe(df, use_container_width=True)

    if st.button("Refresh Telemetry"):
        st.rerun()
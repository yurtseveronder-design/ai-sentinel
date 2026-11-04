
import streamlit as st
import pandas as pd
from telemetry import get_logs_dataframe, DB_NAME
import sqlite3

st.set_page_config(page_title="Telemetry & Audit Logs", page_icon="📈", layout="wide")

st.title("📈 Enterprise Telemetry & Audit Dashboard")
st.markdown("Track historical LLM performance, latency bottlenecks, and prompt experiment logs across your toolkit.")

df = get_logs_dataframe()

if df.empty:
    st.info("No telemetry data recorded yet. Run tests in the Sandbox, Security Auditor, or LLM-as-a-Judge modules to generate logs!")
else:
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total Executions", len(df))
    with col2:
        st.metric("Modules Used", df["module_name"].nunique())
    with col3:
        avg_latency = df["latency_sec"].mean()
        st.metric("Avg Latency", f"{avg_latency:.2f}s")

    st.divider()
    st.subheader("📋 Detailed Experiment Logs")
    st.dataframe(df, use_container_width=True)

    st.divider()
    col_dl, col_clr = st.columns(2)
    
    with col_dl:
        csv = df.to_csv(index=False).encode("utf-8")
        st.download_button(
            label="📥 Download Audit Logs (CSV)",
            data=csv,
            file_name="prompt_toolkit_telemetry.csv",
            mime="text/csv",
            type="primary"
        )
        
    with col_clr:
        if st.button("🗑️ Clear Local Audit Database"):
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM telemetry_logs")
            conn.commit()
            conn.close()
            st.success("Telemetry logs cleared!")
            st.rerun()


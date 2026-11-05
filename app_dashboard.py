import streamlit as st
import requests

st.set_page_config(page_title="BioImmuneShield AI Security Gateway", page_icon="🛡️", layout="wide")

st.title("🛡️ BioImmuneShield: Enterprise AI Security Gateway")
st.markdown("Real-time LLM prompt inspection, threat detection, PII redaction, and session telemetry.")

col1, col2 = st.columns([2, 1])

with col1:
    st.subheader("Live Prompt Inspector")
    session_id = st.text_input("Session ID (Optional for Multi-Turn Tracking)", value="demo-session-001")
    user_prompt = st.text_area("Enter prompt or payload to inspect:", height=150, placeholder="Type a prompt or injection attempt here...")

    if st.button("Inspect Payload", type="primary"):
        if user_prompt.strip():
            try:
                response = requests.post(
                    "http://127.0.0.1:8000/v1/inspect",
                    json={"prompt": user_prompt, "session_id": session_id if session_id else None}
                )
                data = response.json()

                verdict = response.headers.get("X-Shield-Verdict", data.get("action", "UNKNOWN"))

                if verdict == "BLOCK":
                    st.error(f"🚨 VERDICT: {verdict} (Blocked by Security Policy)")
                elif verdict == "FLAG":
                    st.warning(f"⚠️ VERDICT: {verdict} (Flagged for Review)")
                else:
                    st.success(f"✅ VERDICT: {verdict} (Allowed)")

                st.metric("Risk Score", data.get("risk_score", 0.0))
                st.metric("Confidence", f"{data.get('confidence', 0.0) * 100:.1f}%")

                st.markdown("### 📝 Sanitized Payload")
                st.code(data.get("sanitized_text", ""))

                st.markdown("### 🔍 Matched Rules & Telemetry")
                st.write(data.get("matched_rules", []))
                st.write(data.get("reason", ""))

            except requests.exceptions.ConnectionError:
                st.error("Could not connect to FastAPI gateway. Make sure your server is running on port 8000 (`uvicorn ai_sentinel.api.gateway:app --reload`).")
        else:
            st.warning("Please enter a prompt to inspect.")

with col2:
    st.subheader("📊 Gateway Telemetry")
    st.info("To view live Prometheus metrics, ensure your gateway is running and visit [http://localhost:8000/metrics](http://localhost:8000/metrics).")

    st.markdown("### Security Features Active:")
    st.markdown("- NFKC Canonicalization & Homoglyph Resolution")
    st.markdown("- Base64 Obfuscation Decoding")
    st.markdown("- PII & API Secret Scrubbing")
    st.markdown("- Stateful Multi-Turn Session Risk Drift")
    st.markdown("- Thread-Safe Concurrency & Fail-Closed Circuit Breaker")
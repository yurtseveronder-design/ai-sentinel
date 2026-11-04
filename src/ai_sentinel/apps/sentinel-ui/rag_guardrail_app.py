
import streamlit as st
from openai import OpenAI

st.set_page_config(page_title="RAG Guardrail & Evaluation Validator", page_icon="🛡️", layout="wide")

st.title("🛡️ RAG Guardrail & Evaluation Validator")
st.markdown("Test AI responses against strict prompt constraints, factual source context, and hallucination guardrails.")

with st.sidebar:
    st.header("🔑 Configuration")
    api_key = st.text_input("Enter Groq API Key", type="password")
    st.markdown("[Get a free Groq API key here](https://console.groq.com)")
    
    st.divider()
    st.subheader("⚙️ Guardrail Settings")
    selected_model = st.selectbox("Evaluator Model", ["llama3-70b-8192", "openai/gpt-oss-20b", "mixtral-8x7b-32768"], index=0)
    strictness = st.slider("Guardrail Strictness", 0.0, 1.0, 0.2, 0.1)

col1, col2 = st.columns(2)

with col1:
    st.subheader("📥 RAG Inputs & Constraints")
    source_context = st.text_area(
        "Source Context (Retrieved Documents / Knowledge):",
        value="Company policy states that remote employees receive a $500 annual home office stipend. Receipts must be submitted by December 15. Travel expenses are not covered under this stipend.",
        height=120
    )
    user_query = st.text_input("User Query:", value="Can I use my stipend to buy airline tickets for a business trip?")
    ai_response = st.text_area(
        "AI Model Response to Validate:",
        value="Yes, you can use your home office stipend to buy airline tickets for business trips as long as you submit receipts by December 15.",
        height=120
    )
    
    validate_btn = st.button("Run Guardrail Validation 🛡️", type="primary")

with col2:
    st.subheader("📊 Guardrail Evaluation Report")
    
    if validate_btn:
        if not api_key:
            st.error("Please enter your Groq API key in the sidebar.")
        elif not source_context or not user_query or not ai_response:
            st.warning("Please fill in all input fields.")
        else:
            client = OpenAI(base_url="https://api.groq.com/openai/v1", api_key=api_key)
            
            evaluator_prompt = (
                "You are an objective AI Guardrail & Evaluation Engine. Your task is to audit an AI response "
                "against the provided Source Context and User Query.\n\n"
                "Evaluate the following 3 criteria:\n"
                "1. **Faithfulness / Hallucination Check**: Does the AI response contain information NOT present in the source context?\n"
                "2. **Constraint Adherence**: Did the AI follow all policy limitations mentioned in the source?\n"
                "3. **Query Relevance**: Does the response directly and accurately address the user query?\n\n"
                "Provide a clear verdict: **PASS** or **FAIL**, followed by a bulleted breakdown of the audit."
            )
            
            payload = f"Source Context:\n{source_context}\n\nUser Query:\n{user_query}\n\nAI Response to Audit:\n{ai_response}"
            
            with st.spinner("Running guardrail audit..."):
                try:
                    response = client.chat.completions.create(
                        model=selected_model,
                        temperature=strictness,
                        messages=[
                            {"role": "system", "content": evaluator_prompt},
                            {"role": "user", "content": payload}
                        ]
                    )
                    audit_result = response.choices[0].message.content
                    st.success("Audit complete!")
                    st.markdown(audit_result)
                except Exception as e:
                    st.error(f"Audit failed: {e}")
    else:
        st.info("Fill out the RAG context, query, and AI response on the left, then click **Run Guardrail Validation**.")


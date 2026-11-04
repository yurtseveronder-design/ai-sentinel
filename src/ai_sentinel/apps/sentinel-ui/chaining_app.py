
import streamlit as st
from openai import OpenAI

st.set_page_config(page_title="Multi-Step Prompt Chaining Engine", page_icon="⛓️", layout="wide")

st.title("⛓️ Multi-Step Prompt Chaining & Task Pipeline")
st.markdown("Deconstruct complex goals into sequential LLM workflows where the output of one prompt feeds directly into the next.")

with st.sidebar:
    st.header("🔑 Configuration")
    api_key = st.text_input("Enter Groq API Key", type="password")
    
    st.divider()
    st.subheader("⚙️ Engine Settings")
    selected_model = st.selectbox("Pipeline Model", ["llama3-70b-8192", "llama3-8b-8192", "mixtral-8x7b-32768"])

st.subheader("🎯 Pipeline Objective")
user_goal = st.text_area(
    "Enter high-level task for the multi-step pipeline:",
    value="Create a short marketing launch email for a new AI-powered code assistant.",
    height=80
)

run_pipeline = st.button("Execute 3-Step Pipeline 🚀", type="primary")

if run_pipeline:
    if not api_key:
        st.error("Please enter your Groq API key in the sidebar.")
    else:
        client = OpenAI(base_url="https://api.groq.com/openai/v1", api_key=api_key)
        
        # Step 1: Draft Generation
        st.markdown("### 📝 Step 1: Initial Draft Generation")
        with st.spinner("Step 1 running..."):
            step1_prompt = f"Write an initial rough draft or response for this objective: {user_goal}"
            res1 = client.chat.completions.create(
                model=selected_model,
                temperature=0.7,
                messages=[{"role": "user", "content": step1_prompt}]
            )
            draft_output = res1.choices[0].message.content
            st.info(draft_output)
            
        # Step 2: Critique & Refinement
        st.markdown("### 🔍 Step 2: Critical Audit & Enhancement")
        with st.spinner("Step 2 running..."):
            step2_prompt = f"Review the following draft, identify weaknesses, and rewrite it to be much more impactful and professional:\n\n{draft_output}"
            res2 = client.chat.completions.create(
                model=selected_model,
                temperature=0.3,
                messages=[{"role": "user", "content": step2_prompt}]
            )
            critique_output = res2.choices[0].message.content
            st.warning(critique_output)
            
        # Step 3: Final Polishing & Formatting
        st.markdown("### ✨ Step 3: Final Production Polish")
        with st.spinner("Step 3 running..."):
            step3_prompt = f"Take this refined version and format it cleanly with a strong subject line, clear sections, and call-to-action:\n\n{critique_output}"
            res3 = client.chat.completions.create(
                model=selected_model,
                temperature=0.2,
                messages=[{"role": "user", "content": step3_prompt}]
            )
            final_output = res3.choices[0].message.content
            st.success("✅ Final Pipeline Output")
            st.markdown(final_output)
else:
    st.info("Enter your objective above and click **Execute 3-Step Pipeline** to run the multi-stage workflow.")


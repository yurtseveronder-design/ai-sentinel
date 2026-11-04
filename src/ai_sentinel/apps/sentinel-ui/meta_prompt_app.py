
import streamlit as st
from openai import OpenAI

st.set_page_config(page_title="Meta-Prompt Optimizer", page_icon="⚡", layout="wide")

st.title("⚡ Meta-Prompt Optimizer (Automated Prompt Engineer)")
st.markdown("Transform a rough user idea or task into a elite, production-grade system prompt engineered for maximum LLM performance.")

with st.sidebar:
    st.header("🔑 Configuration")
    api_key = st.text_input("Enter Groq API Key", type="password")
    st.markdown("[Get a free Groq API key here](https://console.groq.com)")
    
    st.divider()
    st.subheader("⚙️ Settings")
    selected_model = st.selectbox("Select Optimizer Model", ["llama3-70b-8192", "openai/gpt-oss-20b", "mixtral-8x7b-32768"], index=0)
    temperature = st.slider("Optimization Creativity", 0.0, 1.0, 0.4, 0.1)

col1, col2 = st.columns(2)

with col1:
    st.subheader("🎯 Raw Task Input")
    raw_task = st.text_area(
        "What do you want the AI to do? (Keep it brief or rough)",
        value="Write a response explaining why regular exercise is good for mental health.",
        height=150
    )
    
    target_audience = st.text_input("Target Audience / Tone (Optional)", value="Professionals, encouraging and scientific")
    output_format = st.text_input("Desired Output Format (Optional)", value="Bulleted list with summary")

    optimize_btn = st.button("Optimize Into Expert Prompt 🚀", type="primary")

with col2:
    st.subheader("💎 Generated Production Prompt")
    
    if optimize_btn:
        if not api_key:
            st.error("Please enter your Groq API key in the sidebar.")
        elif not raw_task:
            st.warning("Please enter a raw task.")
        else:
            client = OpenAI(base_url="https://api.groq.com/openai/v1", api_key=api_key)
            
            meta_system_prompt = (
                "You are an elite Prompt Engineer. Your job is to take a rough user task, target audience, "
                "and desired format, and expand it into a comprehensive, high-performance system prompt. "
                "The resulting prompt must define clear Persona, Context, Operational Constraints, Step-by-Step Instructions, "
                "and Output Formatting. Return ONLY the final optimized prompt inside clean markdown code blocks."
            )
            
            user_payload = f"Task: {raw_task}\nAudience/Tone: {target_audience}\nFormat: {output_format}"
            
            with st.spinner("Engineering high-performance prompt..."):
                try:
                    response = client.chat.completions.create(
                        model=selected_model,
                        temperature=temperature,
                        messages=[
                            {"role": "system", "content": meta_system_prompt},
                            {"role": "user", "content": user_payload}
                        ]
                    )
                    optimized_prompt = response.choices[0].message.content
                    st.success("Prompt optimized successfully!")
                    st.code(optimized_prompt, language="markdown")
                except Exception as e:
                    st.error(f"Optimization failed: {e}")
    else:
        st.info("Enter your task on the left and click **Optimize Into Expert Prompt**.")


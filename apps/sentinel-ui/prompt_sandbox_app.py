
import streamlit as st
from openai import OpenAI

st.set_page_config(page_title="Prompt Engineering Sandbox", page_icon="🧪", layout="wide")

st.title("🧪 Multi-Model Prompt Engineering Sandbox")
st.markdown("Compare how different AI models and temperatures respond to the exact same system and user prompts side-by-side.")

with st.sidebar:
    st.header("🔑 Configuration")
    api_key = st.text_input("Enter Groq API Key", type="password")
    st.markdown("[Get a free Groq API key here](https://console.groq.com)")
    
    st.divider()
    st.subheader("⚙️ Test Settings")
    temperature = st.slider("Temperature (Creativity)", 0.0, 1.0, 0.7, 0.1)
    max_tokens = st.slider("Max Response Tokens", 100, 2000, 800, 100)

col1, col2 = st.columns(2)

with col1:
    st.subheader("📝 Prompt Design")
    system_prompt = st.text_area(
        "System Prompt (Role & Rules):",
        value="You are an expert technical writer. Be concise, objective, and structured.",
        height=100
    )
    user_prompt = st.text_area(
        "User Prompt / Task:",
        value="Explain the core difference between monolithic and microservices architecture in 3 bullet points.",
        height=150
    )

with col2:
    st.subheader("🤖 Model Selection (A/B/C Test)")
    model_a = st.selectbox("Model A", ["openai/gpt-oss-20b", "llama3-70b-8192", "mixtral-8x7b-32768"], index=0)
    model_b = st.selectbox("Model B", ["llama3-70b-8192", "openai/gpt-oss-20b", "mixtral-8x7b-32768"], index=0)
    model_c = st.selectbox("Model C", ["mixtral-8x7b-32768", "llama3-70b-8192", "openai/gpt-oss-20b"], index=0)

if st.button("Run Multi-Model Benchmark 🚀", type="primary"):
    if not api_key:
        st.error("Please enter your Groq API key in the sidebar.")
    elif not user_prompt:
        st.warning("Please enter a user prompt.")
    else:
        client = OpenAI(base_url="https://api.groq.com/openai/v1", api_key=api_key)
        
        models_to_test = [("Model A", model_a), ("Model B", model_b), ("Model C", model_c)]
        result_cols = st.columns(3)
        
        for i, (label, model_name) in enumerate(models_to_test):
            with result_cols[i]:
                st.markdown(f"### 📊 {label}")
                st.caption(f"`{model_name}`")
                
                with st.spinner(f"Querying {model_name}..."):
                    try:
                        response = client.chat.completions.create(
                            model=model_name,
                            temperature=temperature,
                            max_tokens=max_tokens,
                            messages=[
                                {"role": "system", "content": system_prompt},
                                {"role": "user", "content": user_prompt}
                            ]
                        )
                        output_text = response.choices[0].message.content
                        st.success("Complete!")
                        st.markdown(output_text)
                    except Exception as e:
                        st.error(f"Error: {e}")


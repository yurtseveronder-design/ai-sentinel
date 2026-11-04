
import streamlit as st
from openai import OpenAI

st.set_page_config(page_title="Few-Shot In-Context Learning Engine", page_icon="🎯", layout="wide")

st.title("🎯 Few-Shot In-Context Learning Engine")
st.markdown("Dynamically inject and test input-output examples to improve model accuracy on complex classification or extraction tasks.")

with st.sidebar:
    st.header("🔑 Configuration")
    api_key = st.text_input("Enter Groq API Key", type="password")
    
    st.divider()
    st.subheader("⚙️ Model Settings")
    selected_model = st.selectbox("Model", ["llama3-8b-8192", "llama3-70b-8192", "mixtral-8x7b-32768"])
    temperature = st.slider("Temperature", 0.0, 1.0, 0.1, 0.1)

col1, col2 = st.columns(2)

with col1:
    st.subheader("📥 Task Definition & Examples")
    task_description = st.text_area(
        "Task Instruction:",
        value="Classify the user sentiment into one of three categories: Positive, Negative, or Neutral, and extract the primary topic.",
        height=80
    )
    
    st.markdown("### 📚 Few-Shot Examples")
    ex1_in = st.text_input("Example 1 - Input", value="I love the battery life on this new phone!")
    ex1_out = st.text_input("Example 1 - Expected Output", value="Sentiment: Positive | Topic: Battery Life")
    
    ex2_in = st.text_input("Example 2 - Input", value="The app crashed three times today when opening settings.")
    ex2_out = st.text_input("Example 2 - Expected Output", value="Sentiment: Negative | Topic: App Stability")

with col2:
    st.subheader("🚀 Live Target Inference")
    target_input = st.text_area(
        "Target Input to Classify:",
        value="Customer support was okay, but the shipping took two weeks longer than promised.",
        height=100
    )
    
    run_btn = st.button("Run Few-Shot Inference ⚡", type="primary")

    if run_btn:
        if not api_key:
            st.error("Please enter your Groq API key in the sidebar.")
        else:
            client = OpenAI(base_url="https://api.groq.com/openai/v1", api_key=api_key)
            
            constructed_prompt = (
                f"Instructions: {task_description}\n\n"
                f"Here are some examples:\n"
                f"Input: {ex1_in}\nOutput: {ex1_out}\n\n"
                f"Input: {ex2_in}\nOutput: {ex2_out}\n\n"
                f"Now evaluate this target input following the exact same format:\n"
                f"Input: {target_input}\nOutput:"
            )
            
            with st.spinner("Processing few-shot inference..."):
                try:
                    response = client.chat.completions.create(
                        model=selected_model,
                        temperature=temperature,
                        messages=[{"role": "user", "content": constructed_prompt}]
                    )
                    st.success("Result:")
                    st.markdown(response.choices[0].message.content)
                except Exception as e:
                    st.error(f"Error: {e}")


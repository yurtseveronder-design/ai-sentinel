import streamlit as st

st.set_page_config(page_title='Enterprise Prompt Engineering Toolkit', page_icon='🚀', layout='wide')

st.title('🚀 Enterprise Prompt Engineering Toolkit')
st.markdown('Select a tool from the sidebar to begin.')

tool = st.sidebar.radio('Select Module:', ['Overview', '1. Sandbox', '2. Optimizer', '3. Guardrails', '4. Few-Shot', '5. Security', '6. Chaining', '7. LLM-as-a-Judge', '8. Telemetry & Analytics', '9. Vector RAG Engine', '10. Autonomous Agent'])

if tool == '1. Sandbox': import prompt_sandbox_app
elif tool == '2. Optimizer': import meta_prompt_app
elif tool == '3. Guardrails': import rag_guardrail_app
elif tool == '4. Few-Shot': import few_shot_app
elif tool == '5. Security': import security_guard_app
elif tool == '6. Chaining': import chaining_app
elif tool == '7. LLM-as-a-Judge': import evaluator_app
elif tool == '8. Telemetry & Analytics': import analytics_app
elif tool == '9. Vector RAG Engine': import rag_engine_app
elif tool == '10. Autonomous Agent': import agent_app
else: st.info('Welcome! Use the sidebar to navigate your toolkit.')

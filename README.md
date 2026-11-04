# AI Sentinel

A simple, modular workspace for AI security, prompt injection defense, and evaluation tools.

## Project Structure

- `packages/sentinel-core`: Core security engine, regex pattern matching, and threat scoring.
- `apps/sentinel-ui`: Streamlit web interfaces for real-time security guardrails and telemetry.

## Quick Start

1. Install the core package:
   ```cmd
   pip install -e packages/sentinel-core
   ```
2. Run the security guard app:
   ```cmd
   python -m streamlit run apps/sentinel-ui/security_guard_app.py
   ```

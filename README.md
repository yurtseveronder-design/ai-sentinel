# ai-sentinel

A lightweight Python security library for checking LLM prompts against common threats, rate-limiting sessions, and running basic safety evaluations.

## Features
- **Prompt Inspection**: Catches known injection signatures, system prompt extraction attempts, and base64 payloads using NFKC normalization.
- **Semantic Check**: Uses basic term-frequency cosine similarity with synonym mapping to catch paraphrased attacks.
- **Rate Limiting**: Sliding-window rate limiter per session with built-in memory cleanup.
- **FastAPI Middleware**: Optional middleware to automatically inspect incoming web requests.
- **CLI Utility**: Quick command-line interface to test prompts directly from your terminal.
- **Evaluation Harness**: Runs a small test suite to measure detection rate, false positives, and latency.

## Installation

Clone the repository and install dependencies:

```bash
git clone [https://github.com/yurtseveronder-design/ai-sentinel.git](https://github.com/yurtseveronder-design/ai-sentinel.git)
cd ai-sentinel
pip install -e .

ai-sentinel/
├── config/
│   └── threat_signatures.yaml
├── src/
│   └── ai_sentinel/
│       ├── api/
│       │   └── gateway.py
│       └── core/
│           └── shield.py
├── tests/
│   ├── test_adversarial.py
│   ├── test_adversarial_matrix.py
│   ├── test_api.py
│   └── test_shield.py
├── pyproject.toml
├── LICENSE.md
└── README.md
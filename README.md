# ai-sentinel

A modular security gateway and evaluation framework for AI-powered applications and RAG systems. This project serves as a practical security prototype designed to inspect prompts, detect injection attempts, and enforce API authentication.

## Key Features
- **Security Gateway (`src/ai_sentinel/gateway/`)**: A FastAPI service featuring strict startup initialization, API key authentication (`X-API-Key`), and payload size limits (`413 Payload Too Large`).
- **Unified Security Shield (`src/ai_sentinel/core/`)**: Scans inputs for adversarial patterns, Base64 obfuscation, Unicode/confusable normalization, and token-window threat signatures.
- **Evaluation Harness (`eval.py`)**: Benchmarks detection efficacy, false-positive rates, and latency against independent test vectors.
- **Test Coverage**: Includes a pytest test suite covering unit tests and gateway validation.

## Project Structure
ai-sentinel/
├── src/ai_sentinel/
│   ├── core/           # SecurityShield, normalizer
│   └── gateway/        # FastAPI application and route endpoints
├── tests/                  # Pytest test suite
└── eval.py                 # Evaluation benchmark harness
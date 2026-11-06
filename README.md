# ai-sentinel

A modular security gateway and evaluation framework for AI-powered applications and RAG systems. This project serves as a practical security prototype designed to inspect prompts, detect injection attempts, enforce API authentication, and benchmark evaluation metrics.

## Key Features

- **Security Gateway (`src/ai_sentinel/gateway/`)**: A FastAPI service featuring startup initialization, API key authentication (`X-API-Key`), and Prometheus telemetry (`/metrics`).
- **Unified Security Shield (`src/ai_sentinel/core/`)**: Scans inputs for adversarial patterns, Base64 obfuscation, and configured threat signatures.
- **Evaluation Harness (`eval.py`)**: Benchmarks detection efficacy, false-positive rates, and p50/p95 latencies against independent test vectors.
- **Test Coverage**: Includes a robust test suite (`tests/`) covering unit tests, integration decorators, rate limiting, and normalizers.

## Project Structure

```text
ai-sentinel/
├── src/
│   └── ai_sentinel/
│       ├── core/           # SecurityShield, normalizer, and config loader
│       ├── gateway/        # FastAPI application and route endpoints
│       └── integrations/   # Python function decorators and LLM wrappers
├── tests/                  # Pytest test suite
└── docs/                   # Architecture and technical documentation
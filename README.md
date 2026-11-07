# ai-sentinel

A modular security gateway and evaluation framework for AI-powered applications and RAG systems. This project is a practical security prototype designed to inspect prompts, detect prompt injections, enforce API authentication, and benchmark detection performance.

---

## Verified Capabilities & Features

* **Security Gateway (`src/ai_sentinel/gateway/`)**: A FastAPI service featuring:
  * Strict fail-safe startup validation (refuses to run if API keys or threat rules are missing).
  * API key authentication via `X-API-Key` headers using constant-time comparison (`secrets.compare_digest`).
  * Input size bounding (rejects payloads exceeding 32,000 characters with HTTP `413 Payload Too Large`).
* **Unified Security Shield (`src/ai_sentinel/core/`)**:
  * Multi-layer normalization pipeline handling NFKC normalization, zero-width character stripping, HTML/URL entity decoding, and Cyrillic/Greek confusable mapping.
  * Robust Base64 extraction with punctuation handling and nested recursive decoding up to depth 3.
  * $O(N)$ single-pass token window engine matching action/target threat signatures efficiently.
* **Empirical Evaluation Harness (`eval.py`)**:
  * Measures detection recall, false positive rates, and p50/p95 latency metrics against independent test vectors.

---

## Project Structure

```text
ai-sentinel/
├── src/ai_sentinel/
│   ├── core/           # SecurityShield, input normalizer
│   └── gateway/        # FastAPI application and route endpoints
├── tests/                  # Pytest test suite
├── eval.py                 # Evaluation benchmark harness
└── Dockerfile              # Non-root container configuration
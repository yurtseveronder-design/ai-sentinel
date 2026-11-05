# AI-Sentinel

A lightweight Python prototype for input inspection and RAG security proxying. It intercepts, normalizes, and inspects prompts before they reach an LLM to defend against basic prompt injection, obfuscation, and PII exposure.

## Features
- **Input Normalization**: Unicode NFKC normalization, homoglyph mapping, and basic base64 decoding.
- **Threat Detection**: Signature/keyword matching, fragmented token checks, and optional vector semantic similarity scoring.
- **Data Protection**: Basic PII and API key redaction.
- **Audit Logging**: JSONL audit trail logging of inspection verdicts.
- **FastAPI Gateway**: Simple `/v1/inspect` inspection endpoint with Prometheus metrics.

## Installation & Testing
```bash
pip install -e .
python -m pytest tests/
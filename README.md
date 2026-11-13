# AI Sentinel

> **Status:** Actively maintained.

AI Sentinel is a modular security and evaluation platform designed for AI-powered RAG (Retrieval-Augmented Generation) systems. It provides lightweight, rule-based prompt injection detection, input sanitization, and structured risk scoring wrapped in a clean FastAPI service.

## Architecture & Modular Layering

AI Sentinel follows strict, deliberate separation of concerns:
* **InputNormalizer (`src/ai_sentinel/core/normalizer.py`)**: Pure, dependency-free sanitization core handling decoding, normalization, and control-character stripping.
* **SecurityShield (`src/ai_sentinel/core/shield.py`)**: Threat evaluation engine sitting on top of the normalizer, executing pattern matching and risk scoring against a configurable `block_threshold`.
* **API Gateway (`src/ai_sentinel/api/gateway.py`)**: Thin FastAPI shell handling transport, API key header validation, and payload routing.

## What It Does / Does Not Do

* **What it does:** Provides deterministic, rule-based detection against known prompt injection vectors, homoglyph bypasses, and credential exfiltration attempts with fail-closed startup validation.
* **What it does not do:** It is not a heavy ML-based classifier; it intentionally avoids complex deep-learning overhead in favor of fast, transparent, and auditable regex and rule-based heuristics.

## Getting Started & Local Development

### Running Tests
Ensure your API key environment variable is set, then execute the pytest test suite:
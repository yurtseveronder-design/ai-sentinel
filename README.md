# AI Sentinel

A modular security and evaluation platform for AI-powered RAG systems. It intercepts incoming prompts, blocks advanced prompt injection attacks, and logs scan telemetry for auditability.

## Core Features

* **Hybrid Guardrail (`BioImmuneShield`)**: Combines exact string matching, collapsed normalization (stripping spaces and symbols), sliding-window fuzzy matching (`SequenceMatcher`), and fallback token intent checks to catch zero-day prompt variations.
* **Multi-Vector Mutation Engine**: Stress-tests security layers against homoglyph exploits, space fragmentation, character encoding (Base64), and nested role-play wrappers.
* **Telemetry & Logging**: Automatically records scan latency, confidence scores, and threat flags into local SQLite databases and JSON payload logs.
* **FastAPI & RAG Integration**: Wire-ready backend pipeline that scans queries before vector retrieval queries execute.

## Project Structure

```text
ai-sentinel/
├── packages/
│   ├── sentinel-core/       # Core security engine, shields, and mutations
│   │   ├── src/sentinel_core/
│   │   └── tests/           # Comprehensive test suite (baseline, mutations, advanced evasion)
│   └── api-tester/          # API integration and benchmarking tools
└── scripts/                 # Production telemetry and monitoring scripts
```

## Running Tests

Verify the entire security and test suite locally using pytest:

```cmd
python -m pytest packages/sentinel-core/tests/ -v
```

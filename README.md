# AI Sentinel: Production-Grade LLM Security & Telemetry

ai-sentinel is a robust, production-ready AI security guardrail and telemetry engine designed to detect advanced prompt injections (including homoglyphs, leetspeak, and multi-token space fragmentation) while maintaining high-throughput performance.

## Architecture Overview

- **sentinel-core**: Core shielding logic handling homoglyph mapping and fuzzy sequence matching.
- **production_telemetry**: SQLite-backed logging capturing raw inputs, safety decisions, threat patterns, and latency metrics in milliseconds.
- **FastAPI App**: Async REST wrapper exposing health checks and scanning endpoints with sub-millisecond response validation.

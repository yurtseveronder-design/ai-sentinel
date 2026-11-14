# AI-Sentinel

Modular security gateway, prompt-injection defense, and evaluation harness for LLM applications in Python.

## Features
- **Heuristic Scorer**: Advanced anomaly weighting and lexical threat detection.
- **Simple Rate Limiter**: In-memory sliding-window request throttling per client identifier.
- **Audit Logger**: Structured JSON telemetry for security inspection events.
- **Normalizer & Shield**: Input sanitization and prompt guardrails.
## Semantic layer (optional)

AI Sentinel can consult [sentinel-semantic](https://github.com/yurtseveronder-design/sentinel-semantic) for intent routing, PII/sensitivity tags and RAG filters. Set:

| Variable | Purpose |
| --- | --- |
| `SENTINEL_SEMANTIC_URL` | Base URL of the semantic service, for example `http://localhost:8100`. Unset = feature off |
| `SENTINEL_SEMANTIC_API_KEY` | Sent as `X-API-Key` when the semantic service requires it |
| `SENTINEL_SEMANTIC_TIMEOUT` | Seconds to wait (default `1.5`) |
| `SENTINEL_RATE_LIMIT_MAX` | Requests allowed per client per minute (default `50`); raise it for benchmarks |

When enabled, `/v1/scan` adds a `semantic` object (`intent`, `guardrail_profile`, `requires_rag`, `sensitivity_tags`, `filters`, `engine`) to its response, and a `maximum_security_block` profile upgrades an ALLOW to a BLOCK. If the semantic service is unreachable, the gateway fails open to its own rule-based verdict.

Run both services together:

```bash
AI_SENTINEL_API_KEY=change-me SEMANTIC_API_KEY=change-me-too docker compose up --build
```

## The whole stack

```
client ──► sentinel-ui gateway ──► ai-sentinel /v1/scan ──► sentinel-semantic /analyze
           (auth, JWT/API key)     (rule-based shield)       (intent, PII, RAG filters)
                                          ▲
                                  api_tests (contracts + end-to-end checks)
```

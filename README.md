# AI-Sentinel

Modular security gateway, prompt-injection defense, and evaluation harness for LLM applications in Python.

## What it does

`POST /v1/scan` takes a prompt and returns `ALLOW` or `BLOCK` with a risk score and reasons. Decision layers:

1. **Normalizer**: Unicode clean-up (zero-width characters, look-alike letters, encodings).
2. **Rule shield**: regular-expression signatures for known attack phrasings in English and nine other languages,
   robust to simple obfuscation (`1gn0re`, `i.g.n.o.r.e`). See `src/ai_sentinel/core/signatures.py`.
3. **Semantic layer (optional)**: [sentinel-semantic](https://github.com/yurtseveronder-design/sentinel-semantic) intent detection.
4. **Gateway protections**: per-API-key rate limit (authenticated requests only), byte-counted 16 KB body limit,
   constant-time key check, request IDs, an audit ledger that stores prompt length and hash rather than text.

## Measured detection quality

Dated **2026-11-14**, `main` at the time, measured with [sentinel-eval](https://github.com/yurtseveronder-design/sentinel-eval)
(details and method in its `RESULTS.md`). The **blind set** (55 prompts, never used to write rules) is the figure to trust:

| Configuration | Attacks blocked | Harmless prompts wrongly blocked |
|---|---|---|
| Default (rules + keyword semantic) | **10%** | 4% |
| Embedding semantic, threshold 0.70 | 23% | 0% |
| Embedding semantic, threshold 0.60 | 47% | 4% |
| Embedding semantic, threshold 0.50 | 73% | 4% (10-17% on harder sets) |

**In plain terms:** the default setup reliably stops the classic English phrases and their obvious variants, and
little else. It is a first line of defence, not a complete one. For better coverage run the semantic layer with the
embedding engine and pick a threshold from the table. Known gaps are listed as expected-failure tests in
`tests/test_signatures.py`. Quoted attack phrases ("explain the 'ignore previous instructions' attack") are blocked too.

## Semantic layer (optional)

AI Sentinel can consult [sentinel-semantic](https://github.com/yurtseveronder-design/sentinel-semantic) for intent routing, PII/sensitivity tags and RAG filters. Set:

| Variable | Purpose |
| --- | --- |
| `SENTINEL_SEMANTIC_URL` | Base URL of the semantic service, for example `http://localhost:8100`. Unset = feature off |
| `SENTINEL_SEMANTIC_API_KEY` | Sent as `X-API-Key` when the semantic service requires it |
| `SENTINEL_SEMANTIC_TIMEOUT` | Seconds to wait (default `1.5`) |

When enabled, `/v1/scan` adds a `semantic` object (`intent`, `guardrail_profile`, `requires_rag`, `sensitivity_tags`, `filters`, `engine`) to its response, and a `maximum_security_block` profile upgrades an ALLOW to a BLOCK. If the semantic service is unreachable or errors (5xx), the gateway **fails open** to its own rule-based verdict. If it rejects the input (4xx such as 422), the request is **blocked**. Long prompts are analysed in overlapping 4,000-character windows.

Run both services together:

```bash
AI_SENTINEL_API_KEY=change-me SEMANTIC_API_KEY=change-me-too docker compose up --build
```

## Gateway settings

| Variable | Default | Purpose |
| --- | --- | --- |
| `AI_SENTINEL_API_KEY` | required | API key for `/v1/scan`; blank values are refused at startup |
| `AI_SENTINEL_BLOCK_THRESHOLD` | `0.7` | Risk score at or above which the rule shield blocks |
| `SENTINEL_RATE_LIMIT_MAX` | `50` | Requests per API key per minute; raise it for benchmarks |

The rate limit is per API key, not per address, and `ai-sentinel serve` ignores `X-Forwarded-For`.

## The whole stack

```
client ──► sentinel-ui gateway ──► ai-sentinel /v1/scan ──► sentinel-semantic /analyze
           (auth, JWT/API key)     (rule-based shield)       (intent, PII, RAG filters)
                                          ▲
                                  api_tests (contracts + end-to-end checks)
```

# API contract (version 1.0.0)

The exact machine-readable contract is [`openapi.json`](../openapi.json) in the repository root (OpenAPI 3.1 with JSON Schema). Tests in `tests/test_openapi_contract.py` check that the real gateway matches it, so the file cannot drift quietly. This page is the human summary.

## Versioning rules

- The contract version (`info.version` in `openapi.json`) is separate from the package version.
- Within `1.x` fields are only **added**, and added fields are optional. Nothing is removed or renamed. **Clients must ignore fields they do not know.**
- A breaking change means `/v2/...` paths. The `/v1/...` paths keep working while `/v2` is introduced, and the removal date is announced in the changelog.
- Request and response bodies are JSON (`Content-Type: application/json`). Maximum body size is 16 KB.

## Authentication

Send `X-API-Key: <key>` on every call except `/health` and `/ready`. `/metrics` also accepts `Authorization: Bearer <key>`. Limit: a per-key rate limit over 60 seconds (HTTP 429 when exceeded).

## `POST /v1/scan`

Request:

```json
{"prompt": "text to check"}
```

Or `{"encoded_prompt": "<base64 of UTF-8 text>"}`. If both are missing or empty, the text is treated as empty and allowed.

Response `200`:

```json
{"status": "blocked", "action": "BLOCK", "risk_score": 1.0, "reasons": ["Matches a known attack phrase pattern"]}
```

| Field | Type | Meaning |
|---|---|---|
| `status` | `"allowed"` or `"blocked"` | Convenience mirror of `action` |
| `action` | `"ALLOW"` or `"BLOCK"` | **The decision. Use this one.** |
| `risk_score` | number | Higher is riskier; not a probability |
| `reasons` | string[] | Why. Never contains the prompt text |
| `semantic` | object, optional | Present when the semantic layer is configured and answered: `intent`, `guardrail_profile`, `requires_rag`, `sensitivity_tags`, `filters`, `engine` |
| `mode`, `would_have_blocked` | optional | Shadow mode only. `action` is then always `ALLOW`; `would_have_blocked` is the real verdict |

Error responses all have the shape `{"detail": "..."}` (except `422`, where `detail` is a list):

| Code | Meaning | What your code should do |
|---|---|---|
| 401 | Missing or wrong key | Fix configuration. Do not send the prompt on |
| 413 | Body over 16 KB | Split or reject |
| 422 | Not valid JSON of the expected shape | Fix the caller |
| 429 | Rate limit | Back off, then retry |
| 503 | Semantic layer is required but did not answer | **No verdict was produced: treat as not allowed** |

## `POST /v1/scan-output`

Request `{"text": "model answer"}`. Response:

```json
{"action": "REDACT", "findings": [{"type": "email", "count": 1}], "redacted_text": "Contact [REDACTED:email]"}
```

`action` is `ALLOW`, `REDACT` (personal data masked; use `redacted_text`) or `BLOCK` (a secret was found; do not show the text). Findings list types and counts, never the matched values. Shadow mode returns `ALLOW` with `would_have`.

## Other endpoints

| Endpoint | Purpose |
|---|---|
| `GET /health` | Liveness. Always `{"status": "ok"}` |
| `GET /ready` | Readiness. `503` when a configured layer is down |
| `GET /metrics` | Prometheus text, key required |

## Compatibility promise in one line

Read `action` (and `action` on output scans); ignore everything you do not recognise; treat any non-200 as "not allowed".

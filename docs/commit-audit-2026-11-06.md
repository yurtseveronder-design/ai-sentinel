# Commit Audit Report (Nov 6, 2026)

This document provides a systematic comparison between commit messages/claims and their actual file diffs for repository commits following `44a976b`.

## Commit Audit Table

| Commit | Claim / Message | Files Changed in Diff | Status | Required Action |
| :--- | :--- | :--- | :--- | :--- |
| `8cc79dd` | Base64 padding, normalizer wiring | Audit file, empty file `dict` | No matching code | Clean empty files, re-implement properly |
| `3097c45` | Middleware fails closed | Audit file only | No matching code | Implement fail-closed middleware logic |
| `db3cd80` | Classifier fails closed | Audit file, empty file `Dict[str` | No matching code | Implement classifier safety policy |
| `98684aa` | OpenAI proxy upgrades | Audit file only | No matching code | Update proxy integration with mocks |
| `6a1a153` | Unicode confusables | Audit file, empty file `str` | No matching code | Restore confusable mappings in normalizer |
| `2ddbfd6` | Action + target rules, stop words | Audit file only | No matching code | Implement YAML token-window rules |
| `ee41d75` | Rate limiter fallback | Empty files `bool`, `window_start` | No matching code | Implement rate limiting dependency |
| `261eff7` | RAG boundaries, output inspection | Empty file `100` | No matching code | Implement RAG chunk verification |
| `111ef29` | Independent evaluation vectors | Empty files, `tuple[int` | No matching code | Establish independent evaluation dataset |

## Behaviors Removed in Rewrite (`bc15b83`)
Commit `bc15b83` replaced core modules and inadvertently removed several key security features:
1. **NFKC Normalization**: Stripping and canonicalization logic in `shield.py`.
2. **Zero-Width, URL & HTML Cleanup**: Sanitization routines in `normalizer.py`.
3. **VectorGuard Similarity Check**: Semantic embedding/cosine similarity validation.
4. **Session History**: Conversation context tracking and stateful poisoning checks.
5. **Rate Limiter**: Request throttling mechanisms.
6. **Audit Logging**: Structured security event emission.
7. **Custom Patterns & Config Path**: Dynamic configuration overrides.
8. **Dynamic Risk Scoring & Mode Sensitivity**: Adjustable risk calculation and mode enforcement.
# Threat model

What ai-sentinel is meant to stop, what it is not, and the assumptions it makes. Read this before relying on it.

## Assets
* The system prompt, credentials and tools available to your LLM.
* Data the model can retrieve (RAG documents) and data it may emit (answers).

## Attackers and entry points
| Entry point | Example | Covered by |
|---|---|---|
| User prompt | "ignore previous instructions ..." | `/v1/scan`: rules, optional semantic layer |
| Retrieved content (indirect injection) | An instruction hidden in a web page, PDF or email | Scan each chunk with `/v1/scan` before it reaches the model (see sentinel-rag-demo) |
| Model output | Leaked key, personal data | `/v1/scan-output` (pattern based) |
| The gateway itself | Brute-forcing keys, flooding, oversized bodies | Constant-time key check, per-key rate limit, 16 KB byte-counted body limit |

## What it does not cover
* **Novel phrasings.** Rules know phrases. On unseen attacks the default configuration blocked about 10% (see sentinel-eval `RESULTS.md`).
  The embedding and classifier options catch more at the cost of more false blocks.
* **Content poisoning** with no instruction in it (a false fact in a document).
* **Quoted attacks.** Discussing an attack phrase looks the same as using it, so such prompts are blocked.
* **Tool and agent abuse** after the model has been convinced; this is a prompt filter, not a sandbox.
* **Multi-turn attacks** spread across messages: each call is judged alone.
* **Non-text inputs** (images, audio).

## Failure behaviour
| Situation | Result |
|---|---|
| sentinel-semantic unreachable or 5xx | Fail **open** to the rule verdict (availability over coverage) |
| sentinel-semantic rejects the input (4xx) | **Block** (the text was never judged) |
| ai-sentinel unreachable from sentinel-ui | sentinel-ui answers 503 (fail **closed**) |
| Shadow mode | Never blocks; reports `would_have_blocked` |

## Operating assumptions
* Keys are distributed over a trusted channel and rotated by you; there is no key management service here.
* Run behind TLS. The service does not terminate TLS and ignores `X-Forwarded-For`.
* The audit ledger stores prompt length and a short hash, not the text. Hashes of short or guessable prompts can be brute-forced.
* A rule-based filter is one layer. Keep least-privilege credentials and human approval for risky tool calls.

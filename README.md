# ai-sentinel

`ai-sentinel` is a lightweight, transparent keyword-filtering and normalization security gateway prototype for local LLM and RAG testing. It is not an enterprise product or a sole defense.

## What it does
- Normalizes input text (NFKC, entity unescaping, zero-width stripping, Cyrillic `і` confusables, and bounded Base64 extraction).
- Scans input against contiguous phrase threat signatures using a token-window matcher.
- Enforces API key authentication (`X-API-Key`) and payload size limits (HTTP 413).

## What it does not do
- It does not contain a semantic machine learning model or vector guardrail.
- It does not protect against complex multi-step indirect prompt injections.
- Session history accumulation is un-capped and disabled by default.

## Usage
```cmd
pip install -e .
set AI_SENTINEL_API_KEY=your-key
set PYTHONPATH=src
python src/ai_sentinel/cli.py serve
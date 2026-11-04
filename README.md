# AI-Sentinel

A lightweight security shield and input analysis framework for AI applications. It intercepts, normalizes, and inspects incoming prompts before they reach language models, protecting against prompt injection, obfuscation, and unauthorized command overrides.

## How It Works

AI-Sentinel processes incoming text through a modular pipeline located in `sentinel_core/`:

1. **Input Normalization (`InputNormalizer`)**:
   - Applies Unicode NFKC normalization to collapse homoglyphs and fullwidth characters.
   - Performs recursive Base64 and encoding decoding to uncover hidden payloads.

2. **Semantic Inspection (`SemanticGuardrail`)**:
   - Compares incoming payloads against security signatures and benign allowlists.
   - Assigns a confidence score and classifies inputs as allowed, blocked, or neutral.

3. **Secure Telemetry (`SecureTelemetryLogger`)**:
   - Logs inspection events and metadata securely for auditing and drift monitoring.

## Project Structure

```text
ai-sentinel/
├── sentinel_core/         # Core single source of truth package
│   ├── __init__.py
│   ├── normalizer.py      # Unicode normalization & recursive decoding
│   ├── classifier.py      # Semantic guardrail & pattern matching
│   ├── telemetry.py       # Event logging & payload hashing
│   └── shield.py          # Unified BioImmuneShield orchestration engine
├── tests/                 # Adversarial test suite
│   └── test_adversarial.py
└── .github/workflows/     # Automated CI/CD test execution
    └── ci.yml
```

## Running Tests

The project includes an adversarial test suite to verify detection and allowlist behavior. Run the tests locally using:

```bash
python -m unittest discover -s tests
```

## Automated CI/CD

All test suites run automatically on GitHub Actions upon pushing changes, ensuring continuous validation against regressions.

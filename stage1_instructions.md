Stage 1: Make One Product That Actually Works (Highest Priority)

Order of execution:

Choose one design and kill the rest (Prompt 1)

Keep the design documented in the README (guardrails/base.py + guardrails/pipeline.py).

Make every plugin inherit BaseGuardrail and implement validate().

Keep one FastAPI app and one pipeline. Delete or move the others to a branch.

Fix CLI and Dockerfile.

Ship the rules and fail closed (Prompt 2)

Move rules inside the package (importlib.resources).

Use the existing fail-closed loader.

Refuse to start if rules are missing/empty.

Report active stages + rule count in /health.

Declare scikit-learn as an optional extra.

Fix CI so it installs the way a user does (Prompt 3)

pip install ".\[test]"

Add coverage gate.

Make CI green on all supported Python versions.

Success criteria for Stage 1:

From an empty directory after pip install ., the gateway starts, loads rules, blocks at least the literal cases, and /health tells the truth.

Stage 2: Make the Tests Honest

Tests must call the product, not decide for it (Prompt 4)

Remove keyword lists and special-case logic from tests.

Add a mutation test that fails when the shield is disabled.

Every test asserts exact expected behaviour through the real entry point.

Create a proper development set + publish honest numbers (Prompt 5)

Build datasets/dev.jsonl (attacks + hard safe prompts, multiple languages).

Create eval.py that reports real TPR/FPR.

Put the numbers in the README with date + commit hash (even if they are low).

Stage 3: Improve Detection (Only after Stage 1 \& 2 are solid)

Stronger rules + better normalizer (Prompt 6)

Action + target style rules (not literal phrases).

Add NFKC, leetspeak view, spaced-letter joining, Base64 decoding.

Support multiple languages if in scope.

Stage 4: Scope, Truth \& Clean-up

Gateway basics (only if it will be network-reachable) – Prompt 7

Scope document, honest README, hygiene, decide on recon/delta\_tracker – Prompt 8


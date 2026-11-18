# Contributing

Thanks for helping. The most useful contributions are **attack prompts we miss** and **harmless prompts we block**.

## Report a miss or a false block (no code needed)

Open an issue with the template "New attack prompt" or "False positive". Please include the exact text, which setup you used (default, or with a classifier) and what you expected. Do not paste real secrets or personal data.

## Run the tests

```bash
pip install -e ".[dev]"
pytest
```

## Adding a rule

1. Add the signature in `src/ai_sentinel/core/signatures.py`.
2. Add a test in `tests/test_signatures.py`: the attack must be blocked, and at least one similar **harmless** sentence must still pass.
3. If you know a case the rule cannot handle, add it as a strict `xfail` with a comment instead of hiding it.

## Rules of the project

- Measure before claiming. Quote numbers from [sentinel-eval](https://github.com/yurtseveronder-design/sentinel-eval), with the dataset named.
- Do not tune rules against the blind set; it is only for reporting.
- Prompt text is never stored in logs or the audit ledger (only length and hash).

Pull requests need the `test` check to pass.

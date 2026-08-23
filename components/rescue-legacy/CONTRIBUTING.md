# Contributing to Codex Rescue

Thank you for contributing to Codex Rescue!

## Development Setup

Install in editable mode:
```bash
pip install -e .
```

Alternatively, set your Python path:
```powershell
$env:PYTHONPATH = "src"
```

## Running Tests

Run unit tests:
```bash
python -m unittest discover -s tests -v
```

Run the fixture validation harness:
```bash
python -m codex_rescue.harness fixtures --output .validation-output/test
```

## Adding Regression Fixtures

Real recovery bugs should become sanitized regression fixtures whenever possible.

To add a sanitized regression fixture:
1. Copy an existing fixture structure.
2. Place it in `fixtures/` or `real-corpus/`.
3. Add `expected.json`.

## Privacy Requirements

- **No raw private rollout files, credentials, tokens, or private prompts in commits.**
- Always sanitize data before including fixtures.
- Explicitly mark `secrets_removed: true` in metadata.

## Invariants

- **Source-session immutability invariant**: `doctor`, `salvage`, and `verify` commands must **never** modify the original Codex rollout. Automated tests verify this invariant.

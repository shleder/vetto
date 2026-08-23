## Description

<!-- Brief description of what this PR does -->

## Checklist

- [ ] Tests added or updated
- [ ] Source session immutability preserved (doctor/salvage/verify do not modify original rollout)
- [ ] No raw private rollout files included
- [ ] Any new fixtures are sanitized (no secrets, tokens, private prompts)
- [ ] Confidence semantics preserved (VERIFIED/RECONSTRUCTED/UNKNOWN)
- [ ] Existing tests pass (`python -m unittest discover -s tests -v`)
- [ ] Fixture harness passes (`python -m codex_rescue.harness fixtures`)

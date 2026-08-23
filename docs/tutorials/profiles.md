# Configuring vetto profiles

Target length: 7 minutes.

1. Run `vetto profiles` and compare default, strict, audit, and permissive.
2. Run `vetto init`, then inspect the generated project policy.
3. Explain `$PROJECT`, `$HOME`, concrete Landlock paths, and load-time globs.
4. Add a read-only tool cache and one explicit environment variable.
5. Demonstrate `extends` and a simple `file_exists` condition.
6. Intentionally add a misspelled field and show that parsing fails instead of
   silently ignoring the rule.
7. Finish with `vetto --dry-run --policy vetto.toml -- command`.

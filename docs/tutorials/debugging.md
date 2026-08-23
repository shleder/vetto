# Debugging blocked operations

Target length: 6 minutes.

1. Start with `vetto doctor --probe` and capture the capability summary.
2. Run an audit-profile session with JSONL and HTML reports.
3. Separate a genuinely blocked operation from a missing observation event.
4. Inspect the policy, resolved path, syscall, process tree, and network mode.
5. Use `vetto report compare` after changing the policy.
6. Explain best-effort secret redaction and review a report before sharing it.
7. Add the narrowest required allow rule; never switch to an unsandboxed
   fallback.

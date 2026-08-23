# ADR 0001: universal rescue architecture

Status: accepted for the `0.2` alpha line

## Context

Vetto owns the trusted runtime boundary around an untrusted agent process.
Codex Rescue owns post-incident diagnostics and recovery for persisted Codex
sessions. The products are being combined under Vetto, but their trust
boundaries must remain separate. Recovery formats vary across agents and
desktop surfaces, while process containment must stay provider-neutral.

## Decision

Vetto keeps one Rust enforcement core and adds a separately namespaced rescue
subsystem. Provider support is implemented through a bounded adapter contract,
not through provider branches in the sandbox backends.

The public commands are provider-neutral:

```text
vetto agents
vetto rescue scan
vetto rescue diagnose <session>
vetto rescue snapshot <session> --output <directory>
vetto rescue fork <session> --output <directory>
```

Adapters may implement these capabilities:

- `detect`
- `discover_sessions`
- `snapshot`
- `diagnose`
- `resume`
- `fork`
- `restore_to_copy`
- `lifecycle_events`
- `protected_launch`

Every capability is independently reported. Unknown tools retain generic
`vetto -- <command>` process protection, but Vetto does not claim deep session
recovery without a verified adapter.

## Security invariants

1. Recovery is read-only by default.
2. Original session files and vendor databases are never modified.
3. Restore and fork operations create a new object with exclusive-create
   semantics; they never overwrite a path.
4. Direct SQLite reconstruction or cursor mutation is prohibited because
   vendor-derived metadata cannot be authoritatively inferred.
5. Inputs have file-count, byte, record-size, time and memory budgets.
6. Adapters run out of process or behind the same bounded Rust interface. They
   cannot weaken policy, enable network access or inherit secrets.
7. Session identifiers are never guessed. Ambiguous identity produces an
   explicit refusal.
8. Every exported artifact is content-hashed and passes the existing
   best-effort sanitizer before it can be shared.
9. MCP, hooks and vendor plugins are integration surfaces, not enforcement
   boundaries.
10. A desktop process is `protected` only when Vetto launched it and retained
    ownership of its process container from creation.

## Support levels

- `protected`: verified process enforcement from launch.
- `integrated`: verified lifecycle events through an official integration.
- `rescue-only`: verified discovery and copy-based recovery.
- `observe-only`: incomplete evidence with no enforcement claim.
- `unsupported`: required capabilities are absent or unverified.

## Repository migration

The historical Codex Rescue tree is imported under `components/rescue-legacy`
with its MIT license and commit ancestry preserved. New Rust rescue code is
Apache-2.0. The original public repository remains available during the alpha
line and receives a migration notice only after the replacement passes its
published acceptance gates.

## Alpha 1 acceptance gates

- the original Codex SQLite mutation cannot be reached, including through a
  hand-edited recovery plan;
- a Codex adapter can discover and diagnose bounded JSONL sessions;
- snapshot/fork operations preserve the source hash and refuse collisions;
- unknown agents still use the generic Vetto process boundary;
- unit, integration, security-smoke and cross-platform release checks pass;
- Git history and release assets pass the documented secret scan;
- the repository is made public only after all preceding gates pass.

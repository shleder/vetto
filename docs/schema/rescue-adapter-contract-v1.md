# Rescue adapter contract v1

Status: frozen for the `0.2` alpha line.

This is the normative contract for the host-side `vetto rescue` surface. The
contract is provider-neutral: adding an adapter must not change the sandbox
backends or weaken their policy. The declarative metadata shape is described by
[`agent-adapter.schema.json`](agent-adapter.schema.json), which rejects unknown
fields with `additionalProperties: false`.

## Registry and support claims

- Adapter IDs are explicit and lower-case. The built-in registry currently
  contains `codex` and an experimental `claude` adapter.
- An unknown adapter is **unsupported** and fails closed with a non-zero exit;
  it must never silently fall back to another adapter.
- Runtime availability is separate from the support claim. A known adapter
  with a missing or invalid state root reports `availability: unavailable` and
  `support_level: unsupported`.
- The only support-level claims are `protected`, `integrated`, `rescue-only`,
  `observe-only`, and `unsupported`.

## Operations

An adapter may implement `detect`, `discover_sessions`, `diagnose`,
`snapshot`, and `fork`. `snapshot` and `fork` are copy-only operations. They
never edit, delete, rename, replace, or reconstruct an original vendor
session/database. A future adapter must explicitly document any additional
capability before it is exposed.

## Bounded input and identity rules

The reference Codex adapter enforces these defaults for every invocation:

| Budget | Default |
| --- | ---: |
| discovered entries | 10,000 |
| all discovered session bytes | 512 MiB |
| one session | 64 MiB |
| one JSONL record | 16 MiB |

Exceeding a discovery or session budget is an error. Oversized JSONL records
are counted as corrupt and are not parsed. Adapters must not recurse through a
symlinked directory, read a symlink as a session, or accept a hard-linked
session alias. A session must remain inside the adapter's canonical state root
and must be read twice with the same SHA-256 digest; a change during the read
is an error.

## Destination rules

Recovery output is created outside the original state root. The destination
parent is canonicalized before the final component is opened. The final path
is created exclusively as a regular file with no symlink following and exactly
one hard link. Existing files, final symlinks, symlinked parents, FIFOs, and
hard-linked destinations are refused without modifying the target.

## JSON output

`--json` output is a stable, machine-readable representation of the public
result types. Internal source paths are omitted. All user-derived strings are
passed through Vetto's best-effort sanitizer before serialization. Consumers
must treat unknown JSON fields as forward-compatible and must not infer a
stronger support level from a missing capability.

## Conformance requirements

An adapter change is conforming only when the rescue test suite covers:

1. unknown adapter rejection as `unsupported`;
2. entry, aggregate-byte, per-session, and per-record budgets;
3. symlink and hard-link source rejection;
4. source-change detection during a read;
5. exclusive, no-follow destination creation outside the source root; and
6. repeatable sanitized JSON output with no credential-shaped input leakage.

The Codex reference adapter is the conformance baseline. Provider-specific
fixtures must be synthetic and must not contain credentials, prompts, or raw
user sessions.

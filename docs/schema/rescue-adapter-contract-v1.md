# Rescue adapter contract v1

Status: frozen for the `0.2` alpha line.

This is the normative contract for the host-side `vetto rescue` surface. The
contract is provider-neutral: adding an adapter must not change the sandbox
backends or weaken their policy. The declarative adapter metadata shape is
described by [`agent-adapter.schema.json`](agent-adapter.schema.json), which
rejects unknown fields with `additionalProperties: false`. The public JSON
result shapes are described separately by
[`rescue-output-v1.schema.json`](rescue-output-v1.schema.json).

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
`snapshot`, and `fork`. `snapshot` and `fork` are copy-only operations. In the
current CLI, `fork` is an alias of the `snapshot` implementation: it creates a
new verified copy and does not claim provider-side resume, reconstruction, or
database mutation. Both operations never edit, delete, rename, replace, or
reconstruct an original vendor session/database. A future adapter must
explicitly document any additional capability before it is exposed.

Provider-derived inventory may be inspected only through a read-only/no-create
database connection. Schema disagreement, a moving cursor, or unreadable
derived state produces a bounded finding or `unknown`; it never authorizes a
repair. Stored provider paths and database values are evidence, not reportable
user content, and must not be emitted verbatim.

## Bounded input and identity rules

The reference Codex adapter enforces these defaults for every invocation:

| Budget | Default |
| --- | ---: |
| filesystem-walk discovered entries | 10,000 |
| all discovered session bytes | 512 MiB |
| one session | 64 MiB |
| one JSONL record | 16 MiB |

Codex `rescue scan` is index-first by default and returns at most 50 verified
provider-index candidates. `--limit N` selects a different positive return
limit, still subject to the bounded discovery and byte budgets. `--all` is the
explicit bounded filesystem walk and is the only scan mode that enumerates
unindexed session files. A missing or unreadable provider index is an error in
index-first mode; it never causes an implicit partial filesystem fallback.

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
result types. The v1 schema covers the scan result, `SessionView` diagnosis,
and the shared copy-only receipt returned by both `snapshot` and `fork`.
Internal source handles and provider state paths are omitted; in particular,
`source_path` is not a public field. All user-derived strings are passed
through Vetto's best-effort sanitizer before serialization. The sanitizer is a
privacy convenience, not an enforcement boundary, so a tester must inspect
every line before sharing a result.

The JSON schema deliberately permits unknown fields in the root and known
objects. Consumers must ignore fields they do not understand and must not
infer a stronger support level from a missing capability. A future field must
not expose internal source handles, raw provider paths, credentials, prompts,
or other private provider state.

For `rescue scan`, the public result contains `sessions` and a `discovery`
object with these fields:

- `mode`: `index-first`, `filesystem-all` for Codex `--all`, or `filesystem`
  for adapters whose normal discovery is filesystem-based (such as Claude);
- `scope`: `provider-index` or `session-roots`;
- `source`: a stable source label such as `sqlite`, `session-index`,
  `session-index+sqlite`, or `session-roots`; it contains no user path;
- `complete`: whether the selected evidence source was fully returned within
  its limit/budget. For `provider-index`, `true` means all verified candidates
  from that index fit within the selected limit. It never proves that the
  provider index covers every file in the state root;
- `limit`: the effective index return limit, or `null` for filesystem
  discovery (including `--all`);
- `candidate_count`: verified candidates from the selected source before the
  return limit;
- `returned_count`: sessions included in `sessions`.

## Conformance requirements

An adapter change is conforming only when the rescue test suite covers:

1. unknown adapter rejection as `unsupported`;
2. entry, aggregate-byte, per-session, and per-record budgets;
3. symlink and hard-link source rejection;
4. source-change detection during a read;
5. exclusive, no-follow destination creation outside the source root; and
6. repeatable sanitized JSON output with no credential-shaped input leakage.

Codex semantic and inventory diagnostics additionally require bounded finding
counts, type-aware persisted-ID checks, call/output correlation limits, and
proof that SQLite bytes are unchanged after every diagnostic path.

The Codex reference adapter is the conformance baseline. Provider-specific
fixtures must be synthetic and must not contain credentials, prompts, or raw
user sessions.

# Vetto alpha field testing

This checklist is for testing a published Vetto npm package on a real local
machine. It is intentionally npm-only: testers do not need Rust, a checkout of
the repository, or a build from `main`.

The supported npm package name is the scoped package
`@shleddy/vetto`. The unscoped `vetto` name is not the installation path.

## Install one published build

Use the `latest` tag for the current stable release and record the exact version printed by
the first command. Do not paste an npm token into an issue and do not install
from a Git URL.

```console
npm install --global @shleddy/vetto
vetto --version
vetto doctor
```

The package contains the native executable for the host platform. It does not
need a Rust toolchain or an install-time binary download. If npm reports an
unsupported platform, record the platform and architecture and stop; do not
work around the package selector by copying a binary from another platform.

For a repeatable test, pin the version shown by `vetto --version` in the issue
and reinstall that exact version when reproducing. The `latest` tag can move
between releases.

## What is supported

Support is a claim about the tested surface, not about the vendor application
as a whole:

| Surface | Current claim | Safe test path |
| --- | --- | --- |
| Codex CLI | `protected` when the process is launched through Vetto; persisted-session inspection is `rescue-only` | Wrap `codex` with `vetto -- ...`; use `vetto rescue` for copy-only inspection |
| Claude Code CLI | `protected` when launched through Vetto; the explicit-root Claude adapter is `rescue-only` and opaque | Wrap `claude` with `vetto -- ...`; pass `--root` for Claude rescue |
| Aider, OpenCode, Copilot, or another CLI | `protected` only for the process actually launched by Vetto | Use the executable command as the final argv after `--`; report the exact command and version |
| Codex/Claude/Cursor/Antigravity desktop GUI | `observe-only` or `unavailable`; Vetto does not inject into an already-running GUI | Test only a documented CLI, if the product has one; never claim that an existing GUI process was sandboxed |

`integrated` is not a blanket claim for a provider. A provider adapter must
earn that level through its adapter contract and fixtures. An unavailable
desktop integration is an honest result, not a failed workaround to hide.

## Baseline commands

Run these from a disposable project directory. The commands only launch a
process through Vetto or inspect state read-only.

```console
vetto doctor
vetto doctor --probe

# Codex CLI, headless smoke test
vetto --profile strict --net off --tui none -- codex exec "print one short test line"

# Claude Code CLI, headless smoke test
vetto --profile strict --net off --tui none -- claude -p "print one short test line"
```

Use the same wrapper for another local CLI, for example:

```console
vetto --profile strict --net off --tui none -- aider --version
```

If the agent needs network access for a test, state the exact allowlist in the
issue. Keep the default `--net off` for the first run. Never pass a secret
through the environment just to make a smoke test pass; Vetto rebuilds the
child environment from an allowlist.

On Windows PowerShell, the same commands work. A desktop application that has
no CLI cannot be wrapped by typing its name into this command: an already
running GUI process is outside this support claim.

## Read-only rescue checks

Rescue never edits the provider state root. Put output in a new directory that
is outside `.codex`, `.claude`, or another agent state directory.

Codex uses `CODEX_HOME`, then the platform home directory. An explicit root is
useful for a fixture or a copied state tree:

```console
# Current stable release
vetto rescue --json scan
vetto rescue --json diagnose "sessions/2026/08/23/session.jsonl"
vetto rescue --json snapshot "sessions/2026/08/23/session.jsonl" --output "./recovery/session.jsonl"
```

Codex scan is index-first and returns at most 50 verified index candidates,
with `--limit N`, explicit `--all`, and the JSON `discovery` object shipping in
the current `0.2.0` package. `discovery.complete` describes only the selected
evidence source; it will not prove that the provider index covers every file under the
state root. The public result shapes are defined in
[`docs/schema/rescue-output-v1.schema.json`](schema/rescue-output-v1.schema.json).

On Windows PowerShell, an explicit Claude root looks like this:

```powershell
vetto rescue --adapter claude --root "$env:USERPROFILE\.claude" --json scan
vetto rescue --adapter claude --root "$env:USERPROFILE\.claude" --json diagnose "projects/example/session.jsonl"
```

The Claude adapter treats provider JSONL as opaque. It does not reconstruct
provider state or write a vendor database. `snapshot` and `fork` are verified,
exclusive copies; an existing destination, a symlink, a changing source, or a
destination inside the source root must fail closed.

For a rescue report, record the adapter, operation, exit code, and whether the
source hash stayed unchanged. Do not use a real session as a public fixture.
Use a synthetic JSONL fixture with fake names and fake content whenever a
reproduction needs an input file.

## Report a result safely

Open the closest issue form:

- **Alpha compatibility test** for a protected CLI launch or a desktop/IDE
  compatibility result;
- **Alpha recovery test** for `scan`, `diagnose`, `snapshot`, or `fork`;
- **Sanitized diagnostic report** for a cross-cutting doctor, environment, or
  support-level result that does not fit the two forms above.

Include only the following, after review:

- Vetto version from `vetto --version` and the agent name/version;
- OS family, OS version, architecture, and whether the run was native or WSL;
- the exact command with project names, usernames, hostnames, and secrets
  replaced by placeholders;
- expected result, actual result, exit code, and a short reproduction;
- sanitized `vetto doctor` output and, when relevant, sanitized `--json` output;
- the selected support level (`protected`, `rescue-only`, `observe-only`, or
  `unsupported`) and why that level is appropriate. `unavailable` describes
  runtime availability and is separate from the `unsupported` support claim;
- for snapshot/fork, confirmation that the source was unchanged and the
  destination did not already exist.

The sanitizer is best-effort, not a guarantee. Inspect every line before
posting. In particular, replace paths even when they look harmless:

```text
C:\Users\alice\project        -> <PROJECT>
/home/alice/.codex             -> <CODEX_HOME>
https://api.example.test/key   -> <URL>
```

Never attach or paste any of the following:

- raw Codex/Claude/agent JSONL, SQLite databases, or copied state directories;
- `auth.json`, `config.toml`, `.env`, shell history, SSH keys, certificates,
  cookies, access tokens, API keys, npm credentials, or cloud credentials;
- prompts, tool arguments, repository source, diffs, private project names, or
  unreviewed home-directory paths;
- a full environment dump, a full command transcript, or an unredacted report;
- a security vulnerability proof-of-concept in a public issue.

If a report may expose a vulnerability or a bypass, stop and use the private
security reporting link in the repository instead of a public issue. Do not
publish a working exploit while asking for a compatibility review.

## Triage expectations

One issue should describe one host, one Vetto version, one agent version, and
one primary failure. Separate unrelated platform results. A result from a
desktop GUI is not evidence that the corresponding CLI is broken, and a
rescue-only finding is not evidence that the launch boundary failed.

Maintainers may request a synthetic fixture or a second run with an explicit
root. They should never request raw vendor state or credentials. A missing
capability, a moving session, an opaque provider schema, and an unsupported
desktop surface are valid bounded outcomes and should remain visible in the
report.

## Alpha gate

The alpha line advances only after the scoped change has a green cross-platform
CI run, focused regression coverage, and a documented limitation. Field tests
can provide evidence, but they do not turn an unverified provider or desktop
integration into a support claim. No tester should publish a release or modify
the provider's state to qualify a result.

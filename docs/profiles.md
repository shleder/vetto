# Profiles and agent compatibility

Vetto policies are parsed strictly. Every policy section and nested key is
known in the schema; an unknown key is an error rather than an ignored
request. The supported policy sections are:

- `[metadata]`: `name`, `description`, and `extends`;
- `[filesystem]`: `allow_write` and `allow_read`;
- `[display_only_deny]`: `paths`;
- `[environment]`: `pass_through`;
- `[limits]`: `cpu_seconds`, `address_space_bytes`, `processes`, and
  `open_files`;
- `[conditions]`: `branch`, `file_exists`, and `project_contains`.

`extends` accepts one built-in profile name or an array of built-in names.
Inheritance is resolved before the child layer and rejects unknown names,
path-like names, and cycles. A project policy cannot inherit an arbitrary
file.

The contextual loader applies layers in this order:

```text
built-in profile -> built-in parents -> agent preset -> project vetto.toml -> CLI-ready overrides
```

Filesystem, deny, and environment lists are additive and deduplicated. No
layer can clear or replace a base deny list or environment allowlist. Agent
presets only add narrowly scoped compatibility read roots; they do not remove
the base profile's restrictions. The legacy `policy::loader::load` API keeps
base-profile-only behavior. Callers that have context should use
`load_with_options` (or `load_with_context`).

Resource limits merge by taking the strictest value supplied by any layer.
They are set for the agent immediately before `execve` in both Linux tiers;
an omitted limit inherits the parent ceiling.

## Conditions

Conditions gate the layer that contains them. A `branch` condition matches the
explicit branch in the load context, or the current local `.git/HEAD` branch
when available. `file_exists` checks non-symlink paths inside the project.
`project_contains` searches regular, non-symlink project files within
a bounded file/byte budget. Unsafe, missing, or uncheckable conditions simply
do not activate that layer.

Conditions are intentionally simple; there is no general expression or
policy language.

## Path variables

`$PROJECT` and `$HOME` retain their existing meanings. With an explicit agent
context, `$AGENT` expands to a fixed safe compatibility root:

| Agent | Root under `$HOME` |
|---|---|
| `codex` | `.codex` |
| `claude` | `.claude` |
| `aider` | `.aider` |
| `cursor` | `.cursor` |
| `cline` | `.cline` |
| `opencode` | `.config/opencode` |
| `copilot` | `.config/github-copilot` |
| `custom` | `.config/vetto/agents/custom` |

Using `$AGENT` without an agent context is an error. Unknown agent names are
rejected instead of becoming a path chosen by input.

## Doctor status

`src/doctor/agent_check.rs` contains an opt-in version probe for the known
agent commands. It invokes `--version` directly (without a shell), drains
output with a cap, and kills a hung child after a bounded timeout. A successful
version probe is only a tested command result. It does not claim “no
conflicts”: registry conflict fields remain unknown until a versioned
compatibility registry is actually tested.

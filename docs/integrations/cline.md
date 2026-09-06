# Sandboxing Cline (VS Code Extension) with Vetto

[Cline](https://github.com/cline/cline) (formerly Claude Dev) is an autonomous AI coding assistant running inside Visual Studio Code. Cline executes terminal commands, reads files, and writes code across your project workspace.

By coupling Cline with **Vetto**, you can let Cline execute shell tasks autonomously with zero fear that a hallucinated command or prompt injection can touch SSH keys, cloud credentials, or files outside your project workspace.

---

## 1. Why Sandbox Cline?

When you grant Cline permission to execute terminal commands (or enable "Always approve terminal commands"):
- The agent has full access to the user account running VS Code.
- A single rogue shell command could read `~/.ssh/id_ed25519`, `~/.aws/credentials`, or exfiltrate private source code over the network.
- Docker containers add excessive latency, break native file watching, and require complex volume mounting.

Vetto solves this with **0ms kernel-level sandboxing** enforced by Linux Landlock and Seccomp-BPF. No root, no Docker, and no changes to your developer workflow.

---

## 2. Fast Setup (Global PATH Shims)

Cline invokes the default terminal configured in VS Code (`bash`, `zsh`, etc.) to run build commands, tests, and scripts.

### Step 1: Install Vetto & Enable Shell Integration
```bash
# 1. Install Vetto
curl -fsSL https://raw.githubusercontent.com/shleder/vetto/main/install.sh | bash

# 2. Install Vetto shell hooks
vetto hook install --scope global
```

This ensures that `~/.vetto/shims` is prepended to the `$PATH` across all interactive and login shells spawned by VS Code.

### Step 2: Ensure VS Code Inherits Vetto Shims
Add the following to your VS Code user `settings.json` (or `.vscode/settings.json` in your project root):

```json
{
  "terminal.integrated.env.linux": {
    "PATH": "${env:HOME}/.vetto/shims:${env:PATH}",
    "VETTO_SANDBOX_ACTIVE": "1"
  }
}
```

Now, any command executed by Cline in the integrated terminal automatically routes through Vetto's security barrier.

---

## 3. Sandboxing Cline CLI Tasks Direct (`vetto --`)

If you run Cline's CLI headless runner or automated test runners:

```bash
vetto -- cline
# Or specify the cline agent preset explicitly:
vetto --agent cline -- cline run "Refactor authentication layer"
```

Vetto automatically applies the `profiles/agents/cline.toml` preset:

```toml
[metadata]
name = "cline"
description = "Safe read-only compatibility roots for Cline."

[filesystem]
# Allow Cline to access local extension caches and logs
allow_read = ["$AGENT/cache", "$AGENT/logs"]

[display_only_deny]
# Strictly mask Cline internal secrets and credential storage
paths = ["$AGENT/secrets.json"]
```

---

## 4. Policy Configuration for Cline Workspaces

By default, Vetto operates in **fail-closed** mode:
- **Write Permission**: Permitted only in your active workspace root (`$PWD`) and `/tmp`.
- **Read Permission**: Permitted for system libraries (`/usr`, `/lib`, `/bin`) and project files.
- **Strict Masking**: `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/gcloud`, and local `.env` files are blocked.

### Example Project `vetto.toml` for Cline
Create a `vetto.toml` in your project root to tune permissions:

```toml
[project]
name = "my-web-app"

[filesystem]
# Allow Cline to read external documentation or shared assets
allow_read = [
    "/usr/local/share/doc",
    "../shared-types"
]

[network]
# Allow Cline to communicate with your chosen LLM provider and package registries
mode = "allowlist"
allow = [
    "api.anthropic.com",
    "api.openai.com",
    "openrouter.ai",
    "registry.npmjs.org",
    "crates.io"
]

[display_only_deny]
paths = [
    ".env",
    ".env.production",
    "secrets/"
]
```

---

## 5. Verifying the Sandbox in Cline

To verify that Cline is properly confined:

1. Open the Cline chat panel in VS Code.
2. Instruct Cline:
   > *"Run a bash command to display the first line of my `~/.ssh/id_rsa` or `~/.aws/credentials`"*
3. Cline executes the command in the terminal.
4. **Result**: The kernel immediately denies the request:
   ```text
   [VETTO GUARD] 🚫 DENIED: Landlock kernel barrier blocked read to ~/.ssh (fail-closed)
   cat: /home/user/.ssh/id_rsa: Permission denied
   ```
5. Cline will recognize the permission barrier and continue safely working only on the allowed workspace files.

---

## 6. Granting Legitimate Access

If Cline needs access to a path outside the workspace (for example, a global cache or toolchain path), grant it directly:

```bash
# Allow read access to a shared library
vetto allow --read-only /opt/custom-sdk

# Allow egress to a private documentation server
vetto allow --net docs.internal.company.com
```

The updated policy takes effect immediately for the next command Cline executes.

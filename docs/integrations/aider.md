# Wrapping Aider with Zero-Config Network Allowlists

[Aider](https://github.com/paul-gauthier/aider) is a leading open-source terminal pair programming tool. Aider interacts with LLMs to edit local files, run linters, execute test suites, and create automatic Git commits.

Wrapping Aider with **Vetto** provides an impenetrable sandbox: Aider can freely read your codebase, write changes, and run tests, while the Linux kernel prevents any rogue test or compromised model from touching your private keys, cloud tokens, or unauthorized network services.

---

## 1. Quick Start (Zero-Config)

### Step 1: Wrap Aider
```bash
vetto enable aider
```

This single command:
1. Detects your existing `aider` binary (whether installed via `pipx`, `pip`, or distro package).
2. Generates an executable shim in `~/.vetto/shims/aider`.
3. Configures PATH priority in your shell profile (`~/.bashrc`, `~/.zshrc`).
4. Associates Aider with the built-in preset (`profiles/agents/aider.toml`).

### Step 2: Check Wrapping Status
```bash
vetto enable --status
```
Output:
```text
aider      [wrapped]    -> ~/.local/bin/aider (preset: default+agent)
```

### Step 3: Run Aider Normally
```bash
aider
# Or with any standard flags:
aider --model sonnet --architect
```

Vetto transparently establishes the kernel sandbox in **0.002s** before Aider initializes.

---

## 2. Zero-Config Network Allowlists

Unlike traditional containers that require opening entire network bridges, Vetto uses kernel network namespaces with an in-process host broker.

### Default Provider Endpoints
By default, `vetto enable aider` activates egress filtering restricted exclusively to:
- `api.openai.com`
- `api.anthropic.com`

Any stray network request (e.g. telemetry trackers, unknown webhooks, or internal LAN ports) is dropped at the socket boundary.

### Configuring Alternate Providers (OpenRouter, DeepSeek, Groq)
If you run Aider against alternate model providers, simply add them in your project's `vetto.toml`:

```toml
[network]
mode = "allowlist"
allow = [
    "api.anthropic.com",
    "api.openai.com",
    "openrouter.ai",
    "api.deepseek.com",
    "api.groq.com",
]
```

Or grant an endpoint dynamically in your terminal:
```bash
vetto allow --net openrouter.ai
```

### Local Models (Ollama / vLLM)
If you run Aider against local models hosted on your machine:

```bash
# Allow communication to local Ollama instance on port 11434
vetto --net strict:127.0.0.1:11434 -- aider --model ollama/deepseek-coder-v2
```

---

## 3. Git Integration Without Credential Exposure

Aider relies heavily on `git` to commit changes and track diffs. Vetto is tuned specifically for this workflow:

- **Project Git Permitted**: Aider has full write access to the local `$PROJECT/.git` directory to commit code and create branches.
- **SSH Keys Protected**: Read access to `~/.ssh/id_rsa`, `~/.ssh/id_ed25519`, and `~/.ssh/config` is strictly denied via Landlock.
- **Git Push Protection**: If Aider runs a command that attempts to push to a remote repository via SSH, Vetto provides policy-controlled forwarding:
  ```bash
  vetto --net=strict:github.com:22 --git-ssh -- aider
  ```
  This passes SSH auth through the host ssh-agent while keeping the private key files inaccessible to the agent.

---

## 4. Sandboxing Automated Test Suites (`--test`)

Aider's `--test` flag allows it to automatically run your test suite (`pytest`, `cargo test`, `npm test`, etc.) and fix errors iteratively.

Running arbitrary test suites is risky because test scripts can execute arbitrary host code. Under Vetto:
- **Write Sandboxing**: Tests can only write to the workspace and `/tmp`. Any attempt to modify system directories or files outside the repo fails immediately.
- **Secret Isolation**: Even if a test prints environment variables or scans the filesystem, Vetto masks your credentials (`.env`, `~/.aws`, `~/.ssh`).
- **Resource Limits**: Prevent rogue tests from consuming infinite memory or spawning fork bombs:
  ```bash
  vetto --limits procs=256,as=4G -- aider --test "npm test"
  ```

---

## 5. Preset Configuration (`profiles/agents/aider.toml`)

Vetto includes a tailored preset for Aider:

```toml
[metadata]
name = "aider"
description = "Safe read-only compatibility roots for Aider."

[filesystem]
# Allow Aider to maintain its internal cache and session logs
allow_read = ["$AGENT/cache", "$AGENT/logs"]

[display_only_deny]
# Strictly deny Aider from reading local unmasked credentials
paths = ["$AGENT/.aider.conf.yml", "$AGENT/.env"]
```

---

## 6. Verification & Troubleshooting

Verify that your Aider session is running safely inside the kernel sandbox:

```bash
# Verify kernel capabilities
vetto doctor

# Check effective permissions and allowed domains for Aider
vetto policy explain --agent aider

# Test boundary enforcement against secrets
vetto verify
```

# Vetto GitHub Action (`vetto-action`)

Run untrusted AI agent commands and build pipelines inside the **Vetto daemon-less sandbox** directly in your GitHub Actions workflows.

No daemon, no Docker-in-Docker required, and zero user-side Rust build overhead. Vetto installs seamlessly via npm/prebuilt binary and wraps your agent process with strict Landlock/Seatbelt kernel confinement.

---

## Usage Examples

### 1. Basic Agent Execution

```yaml
name: Agent Task
on: [push, pull_request]

jobs:
  agent-run:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Sandboxed Agent
        uses: shleder/vetto/action@v0.2.5
        with:
          command: 'npx claude-code -p "Run linter and fix basic formatting"'
```

---

### 2. Custom Policy & Network Allowlist

```yaml
      - name: Run Python Agent with PyPI Egress
        uses: shleder/vetto/action@v0.2.5
        with:
          policy: 'policies/community/python-dev.toml'
          net: 'allowlist:pypi.org,files.pythonhosted.org,github.com'
          command: 'pytest tests/'
```

---

### 3. Fail-On-Block Security Gate + CodeQL SARIF Upload

```yaml
      - name: Strict Security Verification
        uses: shleder/vetto/action@v0.2.5
        with:
          profile: 'strict'
          fail-on-block: '1' # Fails CI if agent attempts to read secrets or escape sandbox
          upload-sarif: 'true'
          command: 'make test'
```

---

## Action Inputs

| Input | Description | Default | Required |
|---|---|---|---|
| `command` | Agent or shell command to execute in sandbox | - | **Yes** |
| `policy` | Path to custom policy TOML or community policy | `""` | No |
| `net` | Network mode (`off`, `allowlist:...`, `strict:...`) | `off` | No |
| `profile` | Built-in profile (`strict`, `default`, `audit`, `permissive`) | `strict` | No |
| `report` | Report formats (`json,sarif`, `html`, `md`) | `json,sarif` | No |
| `report-dir` | Directory for audit reports | `.vetto/reports` | No |
| `version` | Vetto release version or `latest` | `latest` | No |
| `fail-on-block` | Gate CI on blocked security events (`true`, `false`, `N`) | `false` | No |
| `upload-sarif` | Upload generated SARIF report to GitHub Code Scanning | `false` | No |

## Action Outputs

| Output | Description |
|---|---|
| `exit-code` | Exit code of the sandboxed command |
| `sarif-path` | Path to the generated SARIF report file |

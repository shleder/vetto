# Vetto Community Policy Registry

This directory contains curated, battle-tested security policies for common development ecosystems and agent workflows.

To adopt any policy into your project, run:
```bash
vetto policy use <name>
```
This copies the selected policy into `./vetto.toml`.

---

## Available Policies

### 1. `python-dev`
- **File**: [`python-dev.toml`](python-dev.toml)
- **Use case**: Python projects using `uv`, `poetry`, `pip`, or `virtualenv`.
- **Egress**: PyPI package indexes and GitHub.
- **Write scope**: Project directory, pip/uv/poetry caches in `$HOME/.cache`, `$TMPDIR`.

### 2. `node-dev`
- **File**: [`node-dev.toml`](node-dev.toml)
- **Use case**: Node.js and TypeScript applications using `npm`, `yarn`, or `pnpm`.
- **Egress**: npmjs registry, Yarn registry, GitHub.
- **Write scope**: Project workspace, npm/yarn caches in `$HOME`.

### 3. `rust-dev`
- **File**: [`rust-dev.toml`](rust-dev.toml)
- **Use case**: Rust projects using `cargo`, `rustc`, and `cargo-audit`.
- **Egress**: crates.io and static crates CDN.
- **Write scope**: Project workspace, `$HOME/.cargo/registry`, `$HOME/.cargo/git`.

### 4. `java-dev`
- **File**: [`java-dev.toml`](java-dev.toml)
- **Use case**: Java / Kotlin projects using Apache Maven or Gradle.
- **Egress**: Maven Central, Gradle plugin portal and distribution services.
- **Write scope**: Project workspace, `$HOME/.m2/repository`, `$HOME/.gradle/caches`.

### 5. `data-science`
- **File**: [`data-science.toml`](data-science.toml)
- **Use case**: Machine learning and data exploration with Jupyter, PyTorch, and Pandas.
- **Egress**: HuggingFace Hub, PyPI, PyTorch download CDN.
- **Write scope**: Project workspace, torch/huggingface cache directories, Jupyter runtime.

### 6. `read-only-audit`
- **File**: [`read-only-audit.toml`](read-only-audit.toml)
- **Use case**: Security audits, static analysis, and code inspections.
- **Egress**: Network completely disabled (`off`).
- **Write scope**: Strictly denied across project and user home; writes restricted to `$TMPDIR` and `.vetto/reports`.

### 7. `yolo-web`
- **File**: [`yolo-web.toml`](yolo-web.toml)
- **Use case**: Fast-paced web development requiring broad package ecosystem access.
- **Egress**: Multiple major package registries and developer APIs.
- **Write scope**: Project workspace and temporary directories.

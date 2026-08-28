# Vetto Next-Generation (v0.3.0+): 50 Capabilities Engineering Implementation Plan

## 1. Executive Summary
Vetto v0.3.0+ expands from a low-level Linux/macOS process sandbox into a complete **AI Agent Execution Plane & Supervisor**.
All 50 Next-Gen capabilities are implemented on branch `feat/nextgen-50-capabilities` in modular Rust modules under `src/`.

---

## 2. Feature Inventory & Milestone Mapping

| # | Feature | Subsystem | Target Files | Milestone | Status |
|---|---------|-----------|--------------|-----------|--------|
| R1.1 | Native MCP stdio/SSE Sandbox | MCP Protocol Isolation | `src/mcp/mod.rs`, `src/mcp/proxy.rs` | M1 | Complete |
| R1.2 | Granular MCP Tool-Call Authorization Gate | MCP Capability Boundary | `src/mcp/proxy.rs`, `src/mcp/validator.rs` | M1 | Complete |
| R1.3 | Claude Code Native Slash-Command Plugin | Agent Plugins | `src/mcp/delegation.rs`, `src/mcp/proxy.rs` | M1 | Complete |
| R1.4 | AST-based .cursorrules Policy Generator | IDE Ecosystem | `src/mcp/delegation.rs`, `src/mcp/mod.rs` | M1 | Complete |
| R1.5 | Transparent Docker/Podman 0ms Shim | Virtualization Shims | `src/shim/docker.rs`, `src/shim/mod.rs` | M1 | Complete |
| R1.6 | OpenHands / Devin-Style Runtime Adapters | Agent Adapters | `src/mcp/mod.rs`, `src/mcp/delegation.rs` | M1 | Complete |
| R1.7 | Local LLM Socket & VRAM Armor | LLM IPC Security | `src/mcp/mod.rs`, `src/mcp/proxy.rs` | M1 | Complete |
| R1.8 | Multi-Agent Mutual TLS RPC Mesh | Distributed Mesh | `src/mcp/delegation.rs` | M1 | Complete |
| R1.9 | MCP Schema Fuzzing & Argument Validator | MCP Validation | `src/mcp/validator.rs` | M1 | Complete |
| R1.10 | Deterministic JSON-RPC 2.0 Session Replay & Mock | MCP Replay | `src/mcp/replay.rs` | M1 | Complete |
| R1.11 | Dynamic MCP Roots Mount Control | MCP Virtual FS | `src/mcp/proxy.rs`, `src/mcp/validator.rs` | M1 | Complete |
| R1.12 | Streaming SIMD stdio/PTY Buffer Scrubbing | Stream Sanitizer | `src/mcp/replay.rs` | M1 | Complete |
| R1.13 | Prompt Injection Interception & Classifier | AI Security | `src/mcp/validator.rs` | M1 | Complete |
| R1.14 | Cryptographic MCP Session Federation Router | MCP Routing | `src/mcp/mod.rs`, `src/mcp/delegation.rs` | M1 | Complete |
| R1.15 | Hierarchical Subagent Capability Leases | Subagent Leases | `src/mcp/delegation.rs` | M1 | Complete |
| R2.1 | L7 HTTP/HTTPS Method & REST Endpoint Filter | Deep L7 Network | `src/net_l7/mod.rs`, `src/net_l7/acl.rs` | M2 | Complete |
| R2.2 | Dev Server Port Armor (3000, 5173, 8000, 8080) | Port Defense | `src/net_l7/dev_server.rs` | M2 | Complete |
| R2.3 | Background Tunneling & Exfiltration Detector | Tunnel Armor | `src/net_l7/tunnel.rs` | M2 | Complete |
| R2.4 | Outbound API Token Scope Verifier | Secret Guard | `src/net_l7/token.rs` | M2 | Complete |
| R2.5 | DNS Rebinding & Private Network Defense | Network Isolation | `src/net_l7/dev_server.rs`, `src/net_l7/acl.rs` | M2 | Complete |
| R2.6 | TLS SNI Verifier & JA4 Pinning | TLS Security | `src/net_l7/acl.rs`, `src/net_l7/tunnel.rs` | M2 | Complete |
| R2.7 | WebSocket Frame Inspector & Scrubbing | Real-Time Comms | `src/net_l7/dev_server.rs` | M2 | Complete |
| R2.8 | AF_UNIX Local Socket Firewall & FD Inspection | IPC Firewall | `src/net_l7/acl.rs`, `src/net_l7/mod.rs` | M2 | Complete |
| R2.9 | HTTP Request Smuggling Anomaly Detector | HTTP Security | `src/net_l7/acl.rs` | M2 | Complete |
| R2.10 | eBPF Socket-PID Correlation Table | Kernel Telemetry | `src/net_l7/tunnel.rs`, `src/net_l7/mod.rs` | M2 | Complete |
| R2.11 | Ephemeral In-Memory Root CA Generator | MITM Engine | `src/net_l7/token.rs`, `src/net_l7/mod.rs` | M2 | Complete |
| R2.12 | Webhook Gateway with Constant-Time HMAC | Ingress Armor | `src/net_l7/dev_server.rs` | M2 | Complete |
| R3.1 | Infinite Tool-Call Loop & Token Burn Detector | Agent Watchdog | `src/watchdog/throttler.rs`, `src/watchdog/mod.rs` | M3 | Complete |
| R3.2 | Real-Time CoW Micro-Snapshot Engine | CoW Rollback | `src/watchdog/snapshot.rs` | M3 | Complete |
| R3.3 | Multi-Agent Swarm File Lock Scheduler | Multi-Agent Sync | `src/watchdog/lock.rs` | M3 | Complete |
| R3.4 | Automated Sanitized .env.example Synthesizer | Env Security | `src/watchdog/env_gen.rs` | M3 | Complete |
| R3.5 | Crash-Resilient Session WAL Daemon | Recovery Engine | `src/watchdog/snapshot.rs`, `src/watchdog/mod.rs` | M3 | Complete |
| R3.6 | cgroup v2 PSI Resource Pressure Limiter | Resource Guard | `src/watchdog/throttler.rs`, `src/watchdog/mod.rs` | M3 | Complete |
| R3.7 | Syscall Anomaly Pattern Detector | Syscall Monitor | `src/watchdog/env_gen.rs`, `src/watchdog/mod.rs` | M3 | Complete |
| R3.8 | Disk & Inode Space Tripwire | Resource Guard | `src/watchdog/throttler.rs`, `src/watchdog/mod.rs` | M3 | Complete |
| R3.9 | Git Uncommitted Working Tree Seal | State Defense | `src/watchdog/snapshot.rs`, `src/watchdog/env_gen.rs` | M3 | Complete |
| R3.10 | Multi-Agent IPC Deadlock Breaker | Concurrency | `src/watchdog/lock.rs` | M3 | Complete |
| R3.11 | Malicious TTY Escape Sequence Sanitizer | Terminal Armor | `src/watchdog/throttler.rs`, `src/watchdog/mod.rs` | M3 | Complete |
| R3.12 | AST Script Emulator & Dry-Run Engine | Script Guard | `src/watchdog/env_gen.rs` | M3 | Complete |
| R3.13 | Semantic File Mutation Undo-Log | Transactional FS | `src/watchdog/snapshot.rs` | M3 | Complete |
| R4.1 | GitHub Action Workflow & PR Annotator | CI/CD Platform | `src/governance/mod.rs` | M4 | Complete |
| R4.2 | Local Web GUI Dashboard (Axum/WS) | Developer Experience | `src/governance/mod.rs` | M4 | Complete |
| R4.3 | Portable WebAssembly WASI Preview 2 Tier | Multiplatform Tier | `src/wasm/runtime.rs`, `src/wasm/mod.rs` | M4 | Complete |
| R4.4 | Automated Agent SBOM & License Auditor | Compliance | `src/governance/sbom.rs` | M4 | Complete |
| R4.5 | OTLP / Splunk Enterprise Telemetry Forwarder | Telemetry | `src/governance/mod.rs` | M4 | Complete |
| R4.6 | OPA / Rego Policy-as-Code Engine | Policy Engine | `src/governance/mod.rs` | M4 | Complete |
| R4.7 | CI Matrix Security Benchmark Runner | Verification | `src/governance/mod.rs` | M4 | Complete |
| R4.8 | Policy Language Server Protocol (LSP) Engine | IDE Developer | `src/governance/mod.rs` | M4 | Complete |
| R4.9 | Cryptographic Policy Bundle Signer & Verifier | Enterprise Security | `src/governance/merkle.rs`, `src/governance/mod.rs` | M4 | Complete |
| R4.10 | Merkle-Tree Cryptographic Audit Log | Audit Chain | `src/governance/merkle.rs` | M4 | Complete |
| M5 | Top-Level CLI Subcommands & Library Wiring | Integration | `src/lib.rs`, `src/cli.rs`, `src/main.rs`, `src/shim/` | M5 | Complete |

---

## 3. Implemented Modules Architecture

### Milestone 1: Agent Protocols & MCP Capability Boundary (R1: 15 Features)
- `src/mcp/mod.rs`
- `src/mcp/validator.rs`
- `src/mcp/proxy.rs`
- `src/mcp/delegation.rs`
- `src/mcp/replay.rs`
- `src/shim/docker.rs`

### Milestone 2: Deep L7 Network Inspection & Dev Server Protection (R2: 12 Features)
- `src/net_l7/mod.rs`
- `src/net_l7/acl.rs`
- `src/net_l7/dev_server.rs`
- `src/net_l7/tunnel.rs`
- `src/net_l7/token.rs`

### Milestone 3: State Watchdog & Micro-Snapshot Engine (R3: 13 Features)
- `src/watchdog/mod.rs`
- `src/watchdog/throttler.rs`
- `src/watchdog/snapshot.rs`
- `src/watchdog/lock.rs`
- `src/watchdog/env_gen.rs`

### Milestone 4: Developer Ecosystem & Enterprise Governance (R4: 10 Features)
- `src/governance/mod.rs`
- `src/governance/sbom.rs`
- `src/governance/merkle.rs`
- `src/wasm/mod.rs`
- `src/wasm/runtime.rs`

### Milestone 5: Top-Level Integration & CLI Subcommands
- `src/lib.rs` (exposed all new modules)
- `src/cli.rs` (subcommands: `mcp`, `net-l7`/`l7`, `watchdog`, `governance`/`gov`, `wasm`, `ui`)
- `src/main.rs` (execution dispatchers)
- `src/shim/mod.rs` & `src/shim/registry.rs` (docker & podman container shims)

# Vetto v0.2.2+ Architecture, Security Hardening & 30-Step Technical Engineering Roadmap

## 1. Executive Architecture Summary
Vetto v0.2.2+ is designed as a host-native, unprivileged AI coding agent sandbox and security engine. It enforces zero-trust boundaries at the operating system kernel level (Linux Landlock ABI v1-v6 + eBPF/seccomp, macOS Seatbelt + Endpoint Security, Windows AppContainer + Job Objects), provides transparent command interception via shell/git shims, performs zero-overhead streaming redaction of sensitive tokens from PTY feeds, layers multi-tier policies with conditional overrides, strictly isolates subagent IPC and debug ports, and delivers crash-consistent multi-agent session state repair across Claude Code, OpenAI Codex, and Cursor state trees.

---

## 2. Feature Inventory
| # | Feature | Subsystem | Module / Files | Status |
|---|---------|-----------|----------------|--------|
| F01 | Landlock ABI v4-v6 Ruleset & Port Binding | Kernel Sandboxing (Linux) | `src/sandbox/linux/landlock.rs`, `src/sandbox/linux/mod.rs` | Complete |
| F02 | Abstract Socket & Syscall Seccomp Hardening | Kernel Sandboxing (Linux) | `src/sandbox/linux/seccomp_netblock.rs`, `observe_seccomp.rs` | Complete |
| F03 | Native C API Seatbelt (`sandbox_init_with_params`) | Kernel Sandboxing (macOS) | `src/sandbox/macos/seatbelt.rs`, `src/sandbox/macos/mod.rs` | Complete |
| F04 | Endpoint Security AUTH Client & Dispatcher | Kernel Sandboxing (macOS) | `src/sandbox/macos/endpoint_security.rs` | Complete |
| F05 | Native Win32 AppContainer Profile & DACL Injection | Kernel Sandboxing (Windows) | `src/sandbox/windows/appcontainer.rs`, `src/sandbox/windows/mod.rs` | Complete |
| F06 | Windows Job Objects & Low-Integrity Tokens | Kernel Sandboxing (Windows) | `src/sandbox/windows/job_object.rs`, `restricted_token.rs` | Complete |
| F07 | 7-Tier Policy Inheritance & AST Layering | Policy Engine | `src/policy/loader.rs`, `src/policy/types.rs` | Complete |
| F08 | Subtractive Policy Rules & Enterprise Lockdown | Policy Engine | `src/policy/mod.rs`, `src/policy/loader.rs` | Complete |
| F09 | Extended Condition Evaluator (`[conditions]`) | Policy Engine | `src/policy/conditions.rs`, `src/policy/loader.rs` | Complete |
| F10 | Zero-Overhead Streaming PTY Aho-Corasick Redactor | PTY & Streaming | `src/pty/redact.rs`, `src/pty/mod.rs` | Complete |
| F11 | Sliding-Window Shannon Entropy Stream Masking | PTY & Logging | `src/pty/entropy.rs`, `src/logger/sanitizer.rs` | Complete |
| F12 | Zero-Copy ANSI Terminal Escape Passthrough | PTY & Streaming | `src/pty/ansi.rs`, `src/pty/mod.rs` | Complete |
| F13 | Integrated PTY Master / TUI / JSONL Data Pipeline | PTY & TUI | `src/pty/mod.rs`, `src/tui/full.rs`, `src/logger/jsonl.rs` | Complete |
| F14 | CLI `vetto hook install` / `uninstall` / `status` | Developer Tooling & Shims | `src/cli.rs`, `src/cli/hook.rs` | Complete |
| F15 | Fast Native Shim Dispatcher & Recursion Guard | Developer Tooling & Shims | `src/shim/mod.rs`, `src/main.rs` | Complete |
| F16 | Git Transparent Auto-Wrapping (`core.hooksPath`) | Developer Tooling & Shims | `src/cli/git_hook.rs` | Complete |
| F17 | Multi-Shell Environment Hook Generator | Developer Tooling & Shims | `src/cli/shell_env.rs` | Complete |
| F18 | Dynamic Toolchain Binary Shim Registry | Developer Tooling & Shims | `src/init.rs`, `src/shim/registry.rs` | Complete |
| F19 | eBPF Cgroup Socket Redirection (`cgroup_sock_addr`) | Networking & eBPF | `src/sandbox/linux/ebpf_redirect.rs` | Complete |
| F20 | Dual-Mode Network Relay & Dynamic Broker | Networking & Proxy | `src/sandbox/linux/net_relay.rs` | Complete |
| F21 | Local Loopback Debug Port Isolation (`DebugPortGuard`) | Subagent IPC Guardrails | `src/sandbox/linux/debug_guard.rs`, `net_relay.rs` | Complete |
| F22 | Per-Agent Mount & `/dev/shm` Isolation | Subagent IPC Guardrails | `src/sandbox/linux/mounts.rs`, `namespaces.rs` | Complete |
| F23 | Multi-Agent Coordination & Virtual Port Allocation | Multi-Agent Runtime | `src/multi/mod.rs`, `src/multi/runtime.rs` | Complete |
| F24 | Cross-Agent Memory & Signal Protection | Multi-Agent Runtime | `src/multi/isolation.rs`, `src/sandbox/linux/limits.rs` | Complete |
| F25 | Inter-Process Advisory Session Locker (`OFD Locks`) | Rescue Subsystem | `src/rescue/lock.rs` | Complete |
| F26 | SQLite WAL Checkpoint & Recovery Engine | Rescue Subsystem | `src/rescue/wal.rs`, `src/rescue/safe_fs.rs` | Complete |
| F27 | Claude Code JSONL Tail Repair & Project Reconciler | Rescue Subsystem | `src/rescue/claude.rs` | Complete |
| F28 | Codex Monotonic Ordinal Re-Sequencer & Index Sync | Rescue Subsystem | `src/rescue/codex.rs`, `codex_index.rs`, `codex_inventory.rs` | Complete |
| F29 | Cursor State Database (`state.vscdb`) Repair | Rescue Subsystem | `src/rescue/cursor.rs` | Complete |
| F30 | Transactional Repair Receipts & Atomic Rollback | Rescue Subsystem | `src/rescue/mod.rs`, `src/rescue/types.rs`, `rollback.rs` | Complete |

---

## 3. The 30 Sequenced Technical Engineering Steps

### Phase 1: Kernel Sandboxing & OS Primitives Hardening (Steps 1–6)

#### Step 1: Landlock ABI v4–v6 Primitives & Ruleset Expansion
- **Target Files**: `src/sandbox/linux/landlock.rs`, `src/sandbox/linux/mod.rs`
- **Architecture & Data Structures**:
  - Extend `LandlockRulesetAttr`:
    ```rust
    #[repr(C)]
    pub struct LandlockRulesetAttr {
        pub handled_access_fs: u64,
        pub handled_access_net: u64,   // ABI >= 4 (Linux 6.7+)
        pub handled_access_scope: u64, // ABI >= 6 (Linux 6.12+)
    }
    ```
  - Define `LandlockNetPortAttr`:
    ```rust
    #[repr(C)]
    pub struct LandlockNetPortAttr {
        pub allowed_access: u64,
        pub port: u64,
    }
    ```
  - Constants: `LANDLOCK_ACCESS_FS_IOCTL_DEV = 1 << 15`, `LANDLOCK_ACCESS_NET_BIND_TCP = 1 << 0`, `LANDLOCK_ACCESS_NET_CONNECT_TCP = 1 << 1`, `LANDLOCK_RULE_NET_PORT = 2`, `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET = 1 << 0`, `LANDLOCK_SCOPE_SIGNAL = 1 << 1`.
  - Dynamic ABI negotiation: query ABI version via `SYS_LANDLOCK_CREATE_RULESET` (flag `1`), adapt ruleset size parameter (`size = 8` for ABI 1-3, `16` for ABI 4-5, `24` for ABI 6+).
  - PTY whitelist: grant `LANDLOCK_ACCESS_FS_IOCTL_DEV` explicitly to `/dev/ptmx`, `/dev/pts/*`, `/dev/tty` under ABI >= 5.
- **Edge Cases & Failure Modes**: Kernels < 6.7 return `EINVAL` if `size > 8` or if unsupported bitmasks are set. Dynamic fallback down to ABI v1 must degrade gracefully while logging diagnostic warnings.
- **CI Verification**: `cargo test --lib sandbox::linux::landlock::tests`, `cargo test --test integration integration::linux_landlock`.

#### Step 2: Linux Abstract Unix Socket & Seccomp-BPF Filtration Hardening
- **Target Files**: `src/sandbox/linux/seccomp_netblock.rs`, `src/sandbox/linux/observe_seccomp.rs`
- **Architecture & Data Structures**:
  - Static cBPF filter: inspect socket family scalar in `seccomp_data` (`args[0]`); allow `AF_UNIX`, block `AF_INET`/`AF_INET6` in Tier FS-ONLY.
  - Deep Abstract Socket Path Filtration: since classical cBPF cannot dereference user memory pointers (`args[1]`), abstract domain socket filtration (`sun_path[0] == '\0'`) is enforced through:
    1. `CLONE_NEWNET` network namespace isolation (Tier FULL).
    2. Landlock ABI v6 (`LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET`).
    3. `observe_seccomp.rs` (`SECCOMP_RET_USER_NOTIF` + `SECCOMP_FILTER_FLAG_NEW_LISTENER`) reading `/proc/<pid>/mem` for kernel < 6.12 in Tier FS-ONLY.
  - Extend `HARDENING_SYSCALLS` blacklist with modern kernel primitives: `mount_setattr`, `fspick`, `fsmount`, `open_tree`, `fsopen`, `fsconfig`, `move_mount`, `io_uring_setup`, `io_uring_enter`, `io_uring_register`, `userfaultfd`, `pidfd_getfd`, `process_vm_readv`, `process_vm_writev`.
  - Extend `observe_seccomp.rs` thread pool to support `SECCOMP_IOCTL_NOTIF_ADDFD` for synthetic `/dev/null` redirection on sensitive virtual filesystem nodes (`/proc/kcore`, `/proc/kallsyms`).
- **Edge Cases & Failure Modes**: Architecture differences between x86_64 (`SYS_connect` = 42) and aarch64 (`SYS_connect` = 203). Must use architecture-independent BPF macro generators.
- **CI Verification**: `cargo test --lib sandbox::linux::seccomp_netblock::tests`, `cross test --target aarch64-unknown-linux-gnu --lib sandbox::linux::seccomp_netblock::tests`.

#### Step 3: macOS Native C API Seatbelt (`sandbox_init_with_parameters`) Migration
- **Target Files**: `src/sandbox/macos/seatbelt.rs`, `src/sandbox/macos/mod.rs`
- **Architecture & Data Structures**:
  - Eliminate deprecated `/usr/bin/sandbox-exec` subprocess and temporary `/tmp/vetto-seatbelt-*.sb` disk files.
  - Bind dynamically via `libloading` / `dlsym` to `libsandbox.1.dylib`:
    ```c
    int sandbox_init_with_parameters(const char *profile, uint64_t flags, const char *const parameters[], char **errorbuf);
    void sandbox_free_error(char *errorbuf);
    ```
  - Generate in-memory SBPL profile template containing parameter keys: `(param "PROJECT_ROOT")`, `(param "ALLOW_WRITE_DIR_0")`, `(param "DENY_PATH_0")`.
  - Child process invokes `sandbox_init_with_parameters` post-fork before `execve`.
- **Edge Cases & Failure Modes**: Memory management for `errorbuf` on failure; handling macOS SIP restrictions where dyld paths cannot be modified.
- **CI Verification**: `cargo test --test integration integration::macos_seatbelt` on `macos-14` / `macos-latest`.

#### Step 4: macOS Endpoint Security AUTH Engine & Message Dispatcher
- **Target Files**: `src/sandbox/macos/endpoint_security.rs`
- **Architecture & Data Structures**:
  - Define complete C FFI structs: `es_message_t`, `es_event_exec_t`, `es_event_open_t`, `es_event_unlink_t`, `es_event_rename_t`.
  - Upgrade ES subscription from passive NOTIFY to active AUTH: `ES_EVENT_TYPE_AUTH_EXEC`, `ES_EVENT_TYPE_AUTH_OPEN`, `ES_EVENT_TYPE_AUTH_UNLINK`, `ES_EVENT_TYPE_AUTH_RENAME`.
  - Dispatch loop: process events concurrently in a worker pool, evaluating path policies and responding within deadlines via `es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW/DENY, cache_flag)`.
  - Feature gating: fallback to Seatbelt-only when root privileges or entitlement `com.apple.developer.endpoint-security.client` are absent.
- **Edge Cases & Failure Modes**: ES event response timeout causes kernel panic or deadlocks if handler blocks. Worker pool must use dedicated real-time threads with zero heap allocations in the hot path.
- **CI Verification**: `cargo check --features endpoint-security --target aarch64-apple-darwin`, `cargo clippy --features endpoint-security`.

#### Step 5: Windows Native AppContainer Profile & DACL Access Control
- **Target Files**: `src/sandbox/windows/appcontainer.rs`, `src/sandbox/windows/mod.rs`
- **Architecture & Data Structures**:
  - Remove dependency on undocumented `processmodel.dll`.
  - Implement full lifecycle via standard Win32 APIs:
    1. Create AppContainer profile via `userenv.dll!CreateAppContainerProfile`.
    2. Derive AppContainer SID via `DeriveAppContainerSidFromAppContainerName`.
    3. Modify directory DACL using `SetNamedSecurityInfoW`: inject `ACCESS_DENIED_ACE_TYPE` for denied paths (e.g. `.git`, `.env`) placed ahead of `ACCESS_ALLOWED_ACE_TYPE` in the DACL list.
    4. Construct `STARTUPINFOEXW` and assign `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` containing AppContainer SID and capabilities.
    5. Spawn process via `CreateProcessW(EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED)`.
    6. Clean up profile on exit via `userenv.dll!DeleteAppContainerProfile`.
- **Edge Cases & Failure Modes**: NTFS ACL persistence across process crashes. Implement RAII cleanup guards and an orphan profile cleaner during `vetto doctor`.
- **CI Verification**: `cargo test --test integration integration::windows_sandbox` on `windows-latest`.

#### Step 6: Windows Job Objects & Low-Integrity Token Boundary
- **Target Files**: `src/sandbox/windows/job_object.rs`, `src/sandbox/windows/restricted_token.rs`, `src/sandbox/windows/integrity.rs`
- **Architecture & Data Structures**:
  - Create anonymous Job Object with `JOBOBJECT_EXTENDED_LIMIT_INFORMATION`: `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, `JOB_OBJECT_LIMIT_BREAKAWAY_OK` disabled, `JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK` disabled.
  - Create restricted token via `CreateRestrictedToken(DISABLE_MAX_PRIVILEGE, LUA_TOKEN)` and lower integrity level to `SECURITY_MANDATORY_LOW_RID` (`S-1-16-4096`) via `SetTokenInformation(TokenIntegrityLevel)`.
  - Attach suspended process to Job Object before `ResumeThread`.
- **Edge Cases & Failure Modes**: Nested Job Objects on Windows 10/11: ensure `JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK` is explicitly rejected to prevent child processes from breaking out.
- **CI Verification**: `cargo test --lib sandbox::windows::job_object::tests`, `cargo test --lib sandbox::windows::restricted_token::tests`.

---

### Phase 2: Policy Engine & Live PTY Redaction (Steps 7–13)

#### Step 7: Hierarchical 7-Tier Policy Layering Engine & AST
- **Target Files**: `src/policy/loader.rs`, `src/policy/types.rs`, `src/policy/mod.rs`
- **Architecture & Data Structures**:
  - Define `LayeredPolicyLoader` supporting a 7-level precedence hierarchy:
    1. System/Org Global Policy (`/etc/vetto/policy.toml` or `%ProgramData%\vetto\policy.toml`)
    2. User Global Policy (`~/.config/vetto/policy.toml`)
    3. Built-in Profile (`default`, `strict`, `audit`, `permissive`)
    4. Agent Preset (`codex`, `claude`, `cursor`, `aider`)
    5. Repository Policy (`.vetto/policy.toml` or `vetto.toml`) + Fragment Directory (`.vetto/policy.d/*.toml`)
    6. Local Override Policy (`.vetto.override.toml` or `.vetto/local.toml`)
    7. Runtime CLI Flags (`--policy`, `--net`, `--allow-write`, `--deny-read`)
  - Enums and Structs: `PolicySourceKind`, `PolicyLayer`, `MergedPolicy`.
- **Edge Cases & Failure Modes**: Conflicting array orders; deterministic alphabetical sorting for `.vetto/policy.d/*.toml` fragments.
- **CI Verification**: `cargo test --lib policy::loader::tests`, `cargo test --test integration policy_loading`.

#### Step 8: Subtractive Policy Rules & Enterprise Lockdown Security Enforcement
- **Target Files**: `src/policy/mod.rs`, `src/policy/loader.rs`
- **Architecture & Data Structures**:
  - Add subtractive syntax to policy TOML schema: `deny_read = [...]`, `deny_write = [...]`, `deny_network = [...]`, `deny_env = [...]`.
  - Add `[security] immutable = true` directive in System/Org policies (Enterprise Lockdown mode). When `immutable = true`, any attempt by repository or local policies to loosen network modes or whitelist blocked paths causes an immediate parse-time hard error (`VettoError::PolicyLockdownViolation`).
  - Security check: verify `/etc/vetto/policy.toml` is owned by `root` (UID 0) with permissions `0644/0755` on Unix.
- **Edge Cases & Failure Modes**: Subpath collisions (e.g. allow `/home/user/project` but deny `/home/user/project/.git`); path canonicalization must resolve symlinks before applying set difference.
- **CI Verification**: `cargo test --test integration policy_loading -- test_subtractive_and_lockdown`.

#### Step 9: Extended Condition Evaluator (`[conditions]`)
- **Target Files**: `src/policy/conditions.rs`, `src/policy/loader.rs`
- **Architecture & Data Structures**:
  - Expand `RawConditions` and `ConditionEvaluator` with rich contextual predicates:
    ```rust
    pub struct PolicyConditions {
        pub branch: Vec<GlobPattern>,
        pub env_set: Vec<String>,
        pub env_matches: HashMap<String, String>,
        pub agent_is: Vec<String>,
        pub os: Vec<String>,
        pub ci_mode: Option<bool>,
        pub file_exists: Vec<PathBuf>,
        pub git_tag: Vec<GlobPattern>,
    }
    ```
  - Evaluation runtime: evaluate environment variables, active git branch/tag, host OS, and target agent ID before merging layer into active ruleset.
- **Edge Cases & Failure Modes**: Detached HEAD in git repositories; environment variable values containing newlines or null characters.
- **CI Verification**: `cargo test --lib policy::conditions::tests`.

#### Step 10: Zero-Overhead Streaming PTY Redactor (`StreamingRedactor`)
- **Target Files**: `src/pty/redact.rs`, `src/pty/mod.rs`
- **Architecture & Data Structures**:
  - Implement `StreamingRedactor` struct utilizing an Aho-Corasick multi-pattern automaton for high-entropy secret prefixes (`sk-proj-`, `sk-ant-`, `ghp_`, `gho_`, `ghu_`, `AKIA`, `ASIA`, `xoxb-`, `glpat-`, `hf_`, `Bearer `, `-----BEGIN PRIVATE KEY-----`).
  - Implement a 256-byte lookback carry-over ring buffer across chunk reads (4KB–8KB) so tokens split across read boundaries are seamlessly detected.
  - Implement Pad-masking mode (`sk-proj-****************`) to preserve terminal column widths for interactive TUIs.
- **Edge Cases & Failure Modes**: Long tokens exceeding carry-over buffer size; UTF-8 multi-byte sequence split across chunk boundary.
- **CI Verification**: `cargo test --test integration streaming_redaction`.

#### Step 11: Real-time Sliding-Window Shannon Entropy Redaction
- **Target Files**: `src/pty/entropy.rs`, `src/logger/sanitizer.rs`
- **Architecture & Data Structures**:
  - Rolling Shannon entropy evaluator over alphanumeric token runs:
    $$H(X) = -\sum_{i} P(x_i) \log_2 P(x_i)$$
  - Trigger masking if $H > 4.5$ bits/byte on token length $\ge 20$ bytes.
  - Whitelist filter to prevent false positives on hexadecimal hashes (git SHAs `[0-9a-f]{40}`, UUIDs, base64 MIME headers).
- **Edge Cases & Failure Modes**: High-entropy compiled binary strings or base64 embedded images in terminal output. Entropy masking must only trigger on whitespace/delimiter-bounded word tokens.
- **CI Verification**: `cargo test --lib logger::sanitizer::tests`, `cargo test --lib pty::entropy::tests`.

#### Step 12: ANSI Terminal Escape Code Passthrough Engine
- **Target Files**: `src/pty/ansi.rs`, `src/pty/mod.rs`
- **Architecture & Data Structures**:
  - High-performance zero-copy ANSI state machine (supporting CSI `\x1b[...`, OSC `\x1b]...`, and SGR color/style sequences).
  - Isolates text payload bytes from control escape sequences before feeding text into the pattern/entropy matcher.
  - Reassembles sanitized text with original terminal escape formatting without buffer corruption.
- **Edge Cases & Failure Modes**: Malformed or truncated escape sequences at chunk boundaries; nested cursor movements.
- **CI Verification**: `cargo test --lib pty::ansi::tests`.

#### Step 13: Integrated PTY Master / TUI / JSONL Sanitized Data Pipeline
- **Target Files**: `src/pty/mod.rs`, `src/tui/full.rs`, `src/tui/statusline.rs`, `src/logger/jsonl.rs`
- **Architecture & Data Structures**:
  - Refactor `pty::passthrough_once` and `spawn_pipe_reader` in TUI to route raw bytes through `StreamingRedactor` before reaching `io::stdout()` and TUI ring buffers.
  - Unify PTY master output, statusline buffers, and JSONL log writers so unredacted secrets never touch terminal screen or disk logs.
- **Edge Cases & Failure Modes**: High-throughput bursts (e.g. `cat /dev/urandom` or large compilation outputs) must not cause backpressure deadlock or unbounded memory growth.
- **CI Verification**: `cargo test --test integration secret_masking`, `cargo test --test integration tui_rendering`.

---

### Phase 3: Developer Tooling & Transparent Shims (Steps 14–18)

#### Step 14: CLI Subcommands `vetto hook install` / `uninstall` / `status`
- **Target Files**: `src/cli.rs`, `src/cli/hook.rs`
- **Architecture & Data Structures**:
  - Define `HookCommand` enum (`Install`, `Uninstall`, `Status`) with arguments `--scope` (`local` | `global`), `--shells` (`bash`, `zsh`, `fish`, `powershell`, `all`), `--shims` (custom tool list), and `--force`.
  - Implement atomic file modifications for shell startup profiles (`~/.bashrc`, `~/.zshrc`, `~/.config/fish/config.fish`, `$PROFILE`) with marked boundary comments (`# >>> vetto shim environment >>>`).
- **Edge Cases & Failure Modes**: Read-only home directories or missing shell config files; creating directories and files with safe permissions `0700/0600`.
- **CI Verification**: `cargo test cli::tests`, `cargo test --lib cli::hook::tests`.

#### Step 15: Fast Native Shim Dispatcher & Recursive Sandbox Barrier
- **Target Files**: `src/shim/mod.rs`, `src/main.rs`
- **Architecture & Data Structures**:
  - Implement `vetto shim` sub-binary execution flow:
    1. Check for `VETTO_SANDBOXED=1` / `VETTO_SHIM_ACTIVE=1` environment variables. If present: bypass sandbox and directly exec target host binary to avoid recursion.
    2. Resolve target binary: query system `$PATH` filtering out all `~/.vetto/shims` and `.vetto/shims` directories (`find_real_binary`).
    3. Discover nearest project root and load `.vetto/policy.toml`.
    4. Set `VETTO_SANDBOXED=1` and execute command under Vetto supervisor: `vetto -- <real_binary> "$@"`.
- **Edge Cases & Failure Modes**: Circular symlinks in PATH; commands invoked with relative or absolute paths.
- **CI Verification**: `cargo test --test integration shim_interception`.

#### Step 16: Git Auto-Wrapping via `core.hooksPath` & Command Shims
- **Target Files**: `src/cli/git_hook.rs`, `src/cli/hook.rs`
- **Architecture & Data Structures**:
  - Implement Git integration via `git config --global core.hooksPath ~/.vetto/git-hooks` (or local `.git/hooks/`).
  - Create hook scripts for `pre-commit`, `pre-push`, `pre-rebase`, `post-checkout` that execute Git hooks inside the Vetto sandbox.
  - Wrap `git` binary itself in the shim registry to isolate Git operations (preventing rogue `git clone` or malicious hooks from escaping).
- **Edge Cases & Failure Modes**: Existing custom hooks in user repositories: chain execution to existing hooks instead of overwriting.
- **CI Verification**: `cargo test --test integration git_hooks`.

#### Step 17: Multi-Shell Hook Environment Generator (Bash, Zsh, Fish, PowerShell)
- **Target Files**: `src/cli/shell_env.rs`
- **Architecture & Data Structures**:
  - Implement templates and generators for:
    - POSIX / Bash / Zsh: `export PATH="$HOME/.vetto/shims:$PATH"`
    - Fish shell: `set -gx PATH $HOME/.vetto/shims $PATH`
    - Windows PowerShell: `$env:PATH = "$env:USERPROFILE\.vetto\shims;" + $env:PATH`
    - Windows CMD: `set PATH=%USERPROFILE%\.vetto\shims;%PATH%`
- **Edge Cases & Failure Modes**: Windows path separators (`\` vs `/`), path length limits in Windows Registry.
- **CI Verification**: `cargo test --lib cli::shell_env::tests`.

#### Step 18: Dynamic Ecosystem Binary Shim Registry
- **Target Files**: `src/init.rs`, `src/shim/registry.rs`
- **Architecture & Data Structures**:
  - Define `ShimRegistry` maintaining default intercepted developer binaries: `bash`, `zsh`, `sh`, `git`, `node`, `nodejs`, `npm`, `npx`, `pnpm`, `yarn`, `bun`, `deno`, `python`, `python3`, `pip`, `pip3`, `cargo`, `rustc`, `go`, `docker`, `podman`.
  - Provide automatic discovery during `vetto init` and dynamic shim creation based on project toolchain manifest (`Cargo.toml`, `package.json`, `pyproject.toml`, `go.mod`).
- **Edge Cases & Failure Modes**: Non-standard binary locations or version managers (`nvm`, `asdf`, `pyenv`, `rustup`). The shim dispatcher must preserve version manager environment variables.
- **CI Verification**: `cargo test init::tests`, `cargo test --lib shim::registry::tests`.

---

### Phase 4: Network Isolation, eBPF & Subagent IPC Guardrails (Steps 19–24)

#### Step 19: eBPF Cgroup Socket Redirection Subsystem (`cgroup_sock_addr`)
- **Target Files**: `src/sandbox/linux/ebpf_redirect.rs`, `src/sandbox/linux/mod.rs`
- **Architecture & Data Structures**:
  - Create dedicated cgroup v2 for agent session: `/sys/fs/cgroup/vetto/session_<id>/`.
  - Compile and attach eBPF program of type `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` to hooks `BPF_CGROUP_INET4_CONNECT` and `BPF_CGROUP_INET6_CONNECT`.
  - Redirection logic: if destination IP is not loopback (`127.0.0.1`), rewrite `ctx->user_ip4` to `127.0.0.1` and `ctx->user_port` to `htons(RELAY_PORT)`.
  - Maintain `BPF_MAP_TYPE_LRU_HASH` storing mapping `(socket_cookie -> original_dst_ip:port)` for retrieval by the proxy daemon.
- **Edge Cases & Failure Modes**: Absence of `CAP_BPF` / `CAP_NET_ADMIN` or cgroup v2 support; seamless fallback to user-space `net_relay` (`CLONE_NEWNET`).
- **CI Verification**: `cross test --target aarch64-unknown-linux-gnu --lib sandbox::linux::ebpf_redirect::tests`.

#### Step 20: Dual-Mode Network Relay & Dynamic Port Forwarding Broker
- **Target Files**: `src/sandbox/linux/net_relay.rs`
- **Architecture & Data Structures**:
  - Implement dual-mode network broker:
    - Mode A (eBPF): Read `socket_cookie` from BPF map, lookup destination, validate domain/IP against policy allowlist, proxy connection.
    - Mode B (NetNS Relay): Process runs in `CLONE_NEWNET`, listens on `127.0.0.1:47129`, transparently forwards via Unix domain socket with `SCM_RIGHTS`.
- **Edge Cases & Failure Modes**: DNS resolution timeouts and domain spoofing: broker performs host-side DNS resolution with DNS-over-HTTPS / system resolver.
- **CI Verification**: `cargo test --test integration integration::linux_netmodes`.

#### Step 21: Local Loopback Debug Port Isolation (`DebugPortGuard`)
- **Target Files**: `src/sandbox/linux/debug_guard.rs`, `src/sandbox/linux/net_relay.rs`
- **Architecture & Data Structures**:
  - Implement `DebugPortGuard` to block unauthorized connections to sensitive local debugging services:
    - Chrome DevTools (`9222`, `9223`)
    - Node.js Inspector (`9229`, `9230`)
    - Python debugpy (`5678`)
  - Require per-session cryptographic authentication tokens (`X-Vetto-Debug-Token`) for any loopback connection directed to debugging ports.
- **Edge Cases & Failure Modes**: Agent launching its own local test server on port 9229; allow configuration in `[network.debug_ports]` to whitelist internal test ports per agent.
- **CI Verification**: `cargo test --lib sandbox::linux::debug_guard::tests`.

#### Step 22: Per-Agent Mount & `/dev/shm` Isolation
- **Target Files**: `src/sandbox/linux/mounts.rs`, `src/sandbox/linux/namespaces.rs`
- **Architecture & Data Structures**:
  - Mount independent, private `tmpfs` instances for `/tmp` and `/dev/shm` in each agent's mount namespace (`CLONE_NEWNS`).
  - Restrict access to other agents' session directories (`~/.claude/sessions/`, `~/.codex/`, `~/.config/Cursor/`) by mounting read-only empty directories or unbinding paths.
- **Edge Cases & Failure Modes**: `/dev/shm` size exhaustion; enforce `size=64m` limit on private tmpfs mounts.
- **CI Verification**: `cargo test --test integration integration::linux_visibility`.

#### Step 23: Multi-Agent Coordination & Virtual Port Allocation Manager
- **Target Files**: `src/multi/mod.rs`, `src/multi/runtime.rs`
- **Architecture & Data Structures**:
  - Add `DebugPortConfig` to multi-agent manifest:
    ```rust
    #[derive(Debug, Clone, Deserialize, Serialize)]
    pub struct DebugPortConfig {
        pub isolate_devtools: bool,
        pub isolate_node_inspect: bool,
        pub isolate_debugpy: bool,
        pub allowed_ports: Vec<u16>,
    }
    ```
  - `MultiAgentManager` dynamically provisions non-overlapping loopback port ranges and isolated network namespaces for each concurrent subagent.
- **Edge Cases & Failure Modes**: Port collision when concurrent agents request same port; dynamic port NAT remapping.
- **CI Verification**: `cargo test --lib multi::runtime::tests`.

#### Step 24: Cross-Agent Memory & Signal Leakage Protection
- **Target Files**: `src/multi/isolation.rs`, `src/sandbox/linux/limits.rs`
- **Architecture & Data Structures**:
  - Strict PID namespace isolation (`CLONE_NEWPID`) ensuring subagents cannot inspect, signal (`kill`), or attach (`ptrace`) to sibling processes.
  - IPC namespace isolation (`CLONE_NEWIPC`) preventing shared memory segments (shmget) or message queue access across agents.
- **Edge Cases & Failure Modes**: Orphaned zombie processes in sub-PID namespace: Vetto supervisor acts as PID 1 sub-reaper inside the namespace.
- **CI Verification**: `cargo test --test integration integration::linux_subagents`, `cargo test --test integration integration::linux_orphans`.

---

### Phase 5: Multi-Agent Rescue Subsystem & Concurrent State Repair (Steps 25–30)

#### Step 25: Inter-Process Advisory Session Locker (`SessionLockGuard`)
- **Target Files**: `src/rescue/lock.rs`
- **Architecture & Data Structures**:
  - Implement `SessionLockGuard` providing cross-process non-blocking file locking:
    - Linux: `fcntl(fd, F_OFD_SETLK, &flock)` (Open File Description locks, persistent across thread forks and eliminating classic POSIX lock drop on close).
    - macOS: `flock(fd, LOCK_EX | LOCK_NB)`.
    - Windows: `LockFileEx(LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY)`.
  - Lease management: lockfile `.vetto_repair.lock` containing `{ "pid": u32, "acquired_at": u64, "lease_timeout_ms": u64 }`. Exponential backoff retry with timeout detection.
- **Edge Cases & Failure Modes**: Process crashes while holding lock: stale lock detection via PID liveness probe (`kill(pid, 0)` on Unix, `OpenProcess` on Windows) and lease timestamp expiration.
- **CI Verification**: `cargo test --lib rescue::lock::tests`.

#### Step 26: SQLite WAL Checkpoint & Crash-Consistent Recovery Engine
- **Target Files**: `src/rescue/wal.rs`, `src/rescue/safe_fs.rs`
- **Architecture & Data Structures**:
  - Replace fail-closed error on active WAL files (`has active SQLite WAL`) with automated recovery:
    ```rust
    pub struct SqliteWalManager;
    impl SqliteWalManager {
        pub fn checkpoint_and_recover(conn: &mut Connection) -> Result<()> {
            conn.execute_batch("
                PRAGMA busy_timeout = 5000;
                PRAGMA wal_checkpoint(TRUNCATE);
                PRAGMA integrity_check(100);
            ")?;
            Ok(())
        }
    }
    ```
  - Consistent Staging: when taking snapshots of a database with active WAL state, atomically copy `db`, `db-wal`, and `db-shm` as a unified set into the private staging directory before opening or checkpointing.
  - Validate database file descriptor using `O_NOFOLLOW` and verify hardlink count `nlink == 1`.
- **Edge Cases & Failure Modes**: `SQLITE_BUSY` when un-terminated zombie processes hold WAL shared memory locks.
- **CI Verification**: `cargo test --lib rescue::wal::tests`, `cargo test --lib rescue::safe_fs::tests`.

#### Step 27: Claude Code JSONL Tail Repair & Project State Reconciler
- **Target Files**: `src/rescue/claude.rs`
- **Architecture & Data Structures**:
  - Implement stream repair algorithm for corrupted JSONL transcripts (`~/.claude/sessions/*.jsonl`):
    1. Scan backwards from EOF to locate the last complete line terminated by `\n`.
    2. Validate JSON structure of the terminal record via `serde_json::from_str::<Value>()`.
    3. Truncate incomplete byte sequences; insert clean `turn_end` / `session_completed` marker.
  - Reconcile `~/.claude/projects/<hash>/` state index and update `~/.claude.json` metadata while preserving API credentials (`is_credential_path`).
- **Edge Cases & Failure Modes**: Zero-byte JSONL files or files corrupted from byte 0: quarantine corrupted file to `.corrupt.<timestamp>` and initialize minimal valid session schema.
- **CI Verification**: `cargo test --lib rescue::claude::tests`.

#### Step 28: OpenAI Codex Monotonic Ordinal Re-Sequencer & Index Backfill
- **Target Files**: `src/rescue/codex.rs`, `src/rescue/codex_index.rs`, `src/rescue/codex_inventory.rs`
- **Architecture & Data Structures**:
  - Implement ordinal monotonic re-sequencer for Codex rollout JSONL files: resolve `ORDINAL_REGRESSION` and deduplicate `DUPLICATE_ORDINAL_BOUNDARY` records.
  - Index backfill: parse rollout file headers (`session_meta`), construct missing entries in `state_5.sqlite:threads` (`title`, `first_user_message`, `created_at_ms`, `updated_at_ms`), and reset `thread_history_projection_state` offset (`WEDGED_PROJECTION`).
- **Edge Cases & Failure Modes**: Divergence between SQLite thread UUID and JSONL rollout filename: repair mapping in SQLite `threads` table using transactional update.
- **CI Verification**: `cargo test --lib rescue::codex::tests`, `cargo test --lib rescue::codex_index::tests`, `cargo test --lib rescue::codex_inventory::tests`.

#### Step 29: Cursor Agent State Database (`state.vscdb`) & Composer Session Repair
- **Target Files**: `src/rescue/cursor.rs`, `src/rescue/adapter.rs`
- **Architecture & Data Structures**:
  - Implement `CursorAdapter` conforming to `RescueAdapter`:
    - Target paths: `~/.config/Cursor/User/workspaceStorage/<workspace_id>/state.vscdb` (Linux), `~/Library/Application Support/Cursor/User/workspaceStorage/<workspace_id>/state.vscdb` (macOS), `%APPDATA%\Cursor\User\workspaceStorage\<workspace_id>\state.vscdb` (Windows).
    - Parse `ItemTable` keys: `composer.composerData`, `workbench.panel.chatSidebar`, `interactive.sessions`.
    - Repair truncated JSON payloads inside SQLite BLOB/TEXT values and repair `chatEditingSessions/*.jsonl` state files.
- **Edge Cases & Failure Modes**: Cursor workspace ID directory hashing differences across platforms.
- **CI Verification**: `cargo test --lib rescue::cursor::tests`.

#### Step 30: Transactional Repair Receipts & Atomic Rollback Subsystem (`vetto rescue repair` / `rollback`)
- **Target Files**: `src/rescue/mod.rs`, `src/rescue/types.rs`, `src/rescue/rollback.rs`
- **Architecture & Data Structures**:
  - Implement two-phase atomic commit for state repair:
    1. Write repaired content to temporary sibling file `.<file>.vetto_tmp.<pid>.<nonce>`.
    2. Flush to disk via `File::sync_all()`.
    3. Perform atomic swap via `std::fs::rename()` over target file.
    4. Sync parent directory.
  - Generate cryptographically verifiable `RepairReceipt`:
    ```rust
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RepairReceipt {
        pub adapter: String,
        pub session_key: String,
        pub original_sha256: String,
        pub repaired_sha256: String,
        pub backup_archive_path: PathBuf,
        pub actions_applied: Vec<String>,
        pub timestamp_unix_secs: u64,
    }
    ```
  - Implement CLI rollback command: `vetto rescue rollback --receipt <path>` restoring exact pre-repair bytes from backup archive.
- **Edge Cases & Failure Modes**: Power failure during rename: atomic `rename(2)` semantics guarantee that either old or new file is present, never partial data.
- **CI Verification**: `cargo test --lib rescue::tests`, `cargo test --test multi_agent_rescue_ipc_concurrency`.

---

## 4. Comprehensive CI/CD Verification Matrix

All validation must be executed via CI runners in compliance with the local running ban.

```yaml
name: Vetto Complete CI Verification
on: [push, pull_request]

jobs:
  static-and-lints:
    name: Static Analysis & Clippy
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo fmt --all -- --check
      - run: cargo clippy --all-targets --all-features -- -D warnings

  linux-verification:
    name: Linux Kernel Sandboxing & IPC (x86_64 & aarch64)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo test --lib sandbox::linux::landlock::tests
      - run: cargo test --lib sandbox::linux::seccomp_netblock::tests
      - run: cargo test --lib sandbox::linux::debug_guard::tests
      - run: cargo test --lib pty::redact::tests
      - run: cargo test --lib pty::entropy::tests
      - run: cargo test --lib rescue::tests
      - run: cargo test --test integration
      - run: cargo test --test multi_agent_rescue_ipc_concurrency

  macos-verification:
    name: macOS Seatbelt & Endpoint Security
    runs-on: macos-14
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo check --features endpoint-security --all-targets
      - run: cargo test --test integration integration::macos_seatbelt
      - run: cargo test --lib rescue::tests

  windows-verification:
    name: Windows AppContainer & Job Objects
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo test --test integration integration::windows_sandbox
      - run: cargo test --lib sandbox::windows::job_object::tests
      - run: cargo test --lib rescue::tests
```

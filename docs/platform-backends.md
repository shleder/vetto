# Platform backend boundaries

The platform modules expose capability probes and explicit opt-in contracts.
They do not silently elevate, install drivers, create persistent firewall
rules, or claim visibility/enforcement that the operating system API cannot
provide.

---

## 1. Operating System Parity Guarantee Matrix

| Security & Sandboxing Dimension | Linux (Full Tier) | Linux (FsOnly Tier) | macOS (Seatbelt) | Windows (AppContainer / LPAC) | Windows Sandbox (.wsb VM) |
|---|---|---|---|---|---|
| **Filesystem Write Isolation** | Landlock ABI 1-5 + mount namespaces | Landlock filesystem sandbox | Seatbelt SBPL `(allow file-write* ...)` | AppContainer DACL + write grants | Full VM isolation (disposable) |
| **Filesystem Read Isolation** | Landlock scoped reads | Landlock carved allowlists | Known limitation (broad read required for dyld) | AppContainer default-deny | Full VM isolation (disposable) |
| **Intra-Project Secret Masking** | Tmpfs mount overlays over secrets | Sub-allowlist carving | Static profile generation (names visible) | Fail-closed if inside grant root | Isolated VM storage |
| **Network Default-Deny (`--net=off`)** | Network namespace (`CLONE_NEWNET`) | Network namespace / loopback down | Seatbelt `(deny network*)` | AppContainer default-deny | Hyper-V virtual switch disabled |
| **Domain-Filtered Network** | User-space TCP/TLS relay broker | User-space TCP/TLS relay broker | Local proxy broker | WFP image lease (explicit admin opt-in) | Hyper-V virtual switch enabled |
| **Process Lifecycle & Kill-on-Close** | `PR_SET_PDEATHSIG` + pidns init teardown | Process group SIGINT/SIGKILL | Parent death watchdog | Job Object `KILL_ON_JOB_CLOSE` | Hyper-V VM lifecycle management |
| **Resource Limits (CPU / Memory / IO)** | cgroups v2 / `setrlimit` | `setrlimit` | `setrlimit` | Job Object Memory + IO Rate Control | Hyper-V vCPU / RAM limits |
| **System Diagnostics & Audit** | Linux audit netlink feed + seccomp-notify | Linux audit netlink feed | macOS Unified Log (`os_log`) | Windows ETW + Event Log | Windows Event Log |

---

## 2. macOS Backend

### Seatbelt (SBPL) & Regression Tracking
- Vetto generates Seatbelt Profile Language (SBPL) specifications passed to `sandbox-exec`.
- **Known Apple limitation**: Current macOS releases trigger dynamic linker (`dyld`) aborts (SIGABRT) when SBPL read rules are fragmented across multiple path clauses. Vetto explicitly tracks this behavior via `sandbox::macos::seatbelt::probe_sbpl_read_fragment()`, visible in `vetto doctor` under `sbpl-read-fragment`.
- When fragmented read rules are broken on the host OS, Vetto preserves process stability by applying broad read grants while strictly enforcing filesystem write isolation and network denial.

### macOS Unified Logging (`os_log`)
- When `--oslog` or `oslog = true` in policy is enabled, `sandbox::logger::oslog::OsLogSink` streams sandbox events (policy denials, warnings, session lifecycle) to the macOS unified log via `/usr/bin/logger -t vetto`.
- Logging is non-blocking and best-effort: logging failures never interrupt the sandbox session.

### Packaging and Apple Notarization
- `packaging/macos/build_pkg.sh` packages `vetto` into a native `.pkg` installer.
- Supports Hardened Runtime codesigning (`codesign --options runtime`), component package building (`pkgbuild`), Apple notary service submission (`xcrun notarytool submit --wait`), ticket stapling (`xcrun stapler staple`), and Gatekeeper verification (`spctl --assess`).

---

## 3. Windows Backend

### AppContainer & LPAC (Less Privileged AppContainer)
- The default Windows process sandbox runs under an AppContainer token combined with low integrity (`S-1-16-4096`).
- When `--lpac` or `lpac = true` is configured, Vetto validates the Less Privileged AppContainer SID (`S-1-15-2-2`, `ALL RESTRICTED APPLICATION PACKAGES`), stripping implicit package capabilities and isolating local IPC/RPC endpoints.
- `sandbox::windows::probe()` inspects `lpac_api` and reports status in `vetto doctor`.

### Job Object IO Rate Control
- Windows Job Objects enforce `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` to ensure all descendant processes are terminated when Vetto exits.
- When `io_rate` limits are specified (`--limits max_iops=...,max_bandwidth=...`), Vetto sets `JOB_OBJECT_IO_RATE_CONTROL_INFORMATION` (information class 37) on the Job Object, capping IOPS and bandwidth across the sandbox.

### Windows Sandbox VM Opt-in (`--backend win-sandbox`)
- `sandbox::windows::windows_sandbox` generates `.wsb` disposable VM specifications with mapped read-only and read-write folders (`mapped_read_only`, `mapped_read_write`).
- Activated explicitly via `--backend win-sandbox`. Fails closed if Hyper-V virtualization or the Windows Sandbox feature is not enabled.

### Authenticode Digital Signing
- `packaging/windows/sign.ps1` signs `vetto.exe` using `signtool.exe` or `osslsigncode` with SHA-256 and RFC 3161 timestamps (`http://timestamp.digicert.com`).
- Configured in CI release workflows via `SIGNING_CERT_PFX` and `SIGNING_CERT_PASSWORD`.

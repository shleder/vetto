# Security policy and limitations

vetto treats the locally invoked coding agent and every descendant process as
untrusted. It protects developer secrets, files outside the selected project,
network boundaries and process lifetime from malicious model output, prompt
injection, compromised dependencies and buggy automation. It does not defend
against a hostile kernel, root/administrator, physical access, another user
who can modify the operator's files, or a malicious vetto binary.

See [docs/threat-model.md](docs/threat-model.md) for the attack-by-attack
analysis.

## Reporting a vulnerability

Use GitHub's private vulnerability-reporting flow for this repository
(Security → Report a vulnerability). No security email address is advertised
until such an address is actually configured and monitored.

Include the vetto revision, OS/kernel, detected tier, policy, shortest safe
reproducer and whether the result is an enforcement bypass or only a missing
observation event. Never attach real credentials; replace them with test data.

## Enforcement and observation are different

Filesystem/network/process controls are the security boundary. Event feeds,
the TUI and reports are evidence gathered around that boundary and can miss
events. A missing “blocked” row never means the operation was allowed.

- Linux Landlock denials reach the kernel audit stream only on sufficiently
  new kernels (currently kernel 6.12 or newer), and an unprivileged process
  usually cannot read that stream without audit privileges. vetto probes it
  and normally reports it unavailable while enforcement remains active.
- `--observe-seccomp` is optional. Its default mode responds with
  `SECCOMP_USER_NOTIF_FLAG_CONTINUE`; paths copied from another process are
  racy and are used only for display. `SECCOMP_IOCTL_NOTIF_ID_VALID` narrows
  the notification race but does not turn the path into an enforcement input.
- Any seccomp `ADDFD` substitution mode is separately opt-in and changes
  syscall behaviour. It is not described as observation-only and is never
  enabled by `--observe-seccomp` alone.
- Linux allowed-file visibility polls `/proc` adaptively. Short opens and
  short-lived processes can be missed.
- macOS FSEvents reports coarse directory changes after they occur. It does
  **not** report file reads, Seatbelt denials, or a complete per-process audit
  trail. FSEvents must never be presented as file-read visibility.

## Linux tiers

FULL requires Landlock and unprivileged user namespaces. It combines user,
mount, PID, network and IPC namespaces, Landlock, secret overlays and seccomp.
The PID-namespace init reaps and terminates descendants when vetto exits.

FS-ONLY is the fail-closed fallback when Landlock works but user namespaces do
not. It retains Landlock and inherited seccomp, but no mount/PID/network
namespace exists. Project enumeration errors and the safety budget return an
error; there is no broad read fallback. Lifecycle cleanup uses
`PR_SET_PDEATHSIG` plus a process group. A grandchild that deliberately calls
`setsid()` can escape cleanup in this tier, although it still inherits
Landlock and seccomp restrictions.

If neither tier can establish its advertised controls, the command does not
run.

## Filesystem and secret overlays

Landlock is an allowlist evaluated on the resolved inode. It cannot subtract
`$PROJECT/.env` from an allowed project root. FULL therefore bind-mounts
`/dev/null` over secret files and an empty private tmpfs over secret
directories before Landlock is restricted. FS-ONLY constructs narrower
concrete read rules and fails closed if it cannot do so.

The agent retains no usable way to dismantle this view: seccomp rejects
`umount2`, the mount API and `pivot_root`, and descendants inherit the filter.
Report/JSONL destinations are opened outside the sandbox with exclusive,
no-follow semantics and regular-file checks. The secret sanitizer applied to
reports is **best-effort** and can have both false positives and false
negatives; it is not a confidentiality guarantee.

`~/.gitconfig` is intentionally readable for commit identity. A user who
stores credentials in URL rewrites inside that file exposes those credentials
to the agent and should move them to a credential helper.

## Process and kernel hardening

Both Linux tiers reject cross-process access through `ptrace`,
`process_vm_readv`, `process_vm_writev` and `pidfd_getfd`. The filter also
rejects `io_uring_setup/enter/register`, `userfaultfd`, mount manipulation,
kernel module/kexec operations, `bpf`, `perf_event_open`, reboot and swap
control. This intentionally makes debuggers, eBPF loaders, kernel tools and
hardware profilers incompatible inside the sandbox; see the rationale in the
threat model.

FULL mounts an isolated, size-limited `/dev/shm`. Processes within one sandbox
can still communicate with each other through that shared memory because they
are members of the same trust boundary. Resource limits reduce accidental or
malicious exhaustion but are not a defense against every host-level denial of
service.

## Network policy and DNS rebinding

Network `off` is the default. Allowlist/strict connections use a host-side
broker; the child has no direct Internet route. The broker validates the DNS
name, resolves it outside the sandbox, rejects the entire answer set if it
contains loopback/private/link-local/shared/metadata/multicast/reserved IPv4 or
IPv6 (including mapped/NAT64 forms), then connects directly to one validated
`SocketAddr`. The name is not resolved a second time for that connection.

This is CONNECT-level mediation, not content inspection. vetto never performs
TLS interception, SNI filtering, CA installation or credential injection.
Non-proxy protocols fail closed unless an explicit relay exists. `--git-ssh`
uses the same broker and still requires an allowlisted host/port.

## Environment variables

The child environment is allowlist-only. Built-in profiles preserve basic
terminal, locale, editor and toolchain-location variables. `GH_TOKEN`,
`OPENAI_API_KEY`, `ANTHROPIC_API_KEY` and `AWS_*` are not passed by default.
An exact name added to `[environment].pass_through` is an explicit choice to
expose that value to the agent. Unknown policy fields are errors so a misspelt
environment restriction cannot silently disappear.

## macOS

The macOS backend uses `sandbox-exec`/Seatbelt. Apple has deprecated and does
not document `sandbox-exec`; it works on current systems but is a platform
risk. If the runner or required policy behaviour is unavailable, vetto must
fail closed rather than execute unsandboxed.

Endpoint Security support is optional and requires Apple's
`com.apple.developer.endpoint-security.client` entitlement, appropriate code
signing and system approval. Enabling the Cargo feature does not grant the
entitlement. Doctor reports present/absent/unavailable and the backend falls
back to Seatbelt enforcement plus coarse FSEvents changes when ES cannot be
used.

## Windows

Windows uses different primitives; it must not be described as Landlock-like.
The native path capability-probes the experimental Windows 11 process-sandbox
API, AppContainer capabilities, restricted/low-integrity tokens and Job Object
kill-on-close. Experimental API availability can change between Windows
builds. A Job Object or Low integrity token alone is not a filesystem/network
sandbox, so vetto refuses to launch when the complete selected boundary cannot
be established.

Firewall/WFP mutation, Event Log source registration, some ETW providers and
minifilter installation require administrator rights. Optional integrations
must report that requirement and never prompt for or manufacture elevation.
An already-installed signed minifilter may be detected, but its absence cannot
be relabelled as enforcement. Windows Sandbox is a separate opt-in
hardware-virtualized tier and explicitly breaks the “no VM dependency”
property; it is never a silent fallback.

## Residual risks

- Kernel vulnerabilities can bypass kernel-enforced sandboxes.
- An allowed project file created after load may not match a secret glob until
  the next session, depending on tier and overlay availability.
- Proxy-aware allowlists constrain destinations, not what an allowed service
  does with uploaded data.
- Visibility feeds and sanitization are incomplete by design.
- Availability controls are bounded mitigations, not hard real-time quotas.
- User-selected pass-through variables, read roots, network destinations and
  permissive profiles deliberately widen the boundary.

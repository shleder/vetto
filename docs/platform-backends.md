# Platform backend boundaries

The platform modules expose capability probes and explicit opt-in contracts.
They do not silently elevate, install drivers, create persistent firewall
rules, or claim visibility/enforcement that the operating system API cannot
provide.

## Windows

- The process sandbox uses a Job Object with kill-on-close and the Windows 11
  experimental `processmodel.dll` path when the export and AppContainer APIs
  are available. A missing API fails closed. The published schema supports
  read/write and read-only path grants; an unverified denied-path field is
  rejected rather than advertised as enforced.
- `sandbox::windows::firewall` uses an ephemeral WFP session only through an
  explicit caller request. Windows user-mode ALE filters do not provide a
  reliable process-ID condition, so `install_for_process` refuses to create a
  broad executable-image rule. `install_for_image` requires explicit consent
  and scopes the lease to the image path. Domains are not passed to WFP;
  callers must supply broker-resolved, pinned TCP IP/port endpoints. Filters are
  marked enforced only after read-back, and lease drop removes them.
- `sandbox::windows::windows_sandbox` renders and optionally launches a `.wsb`
  disposable VM only after the launcher/virtualization capability gates and
  explicit opt-in. Launcher presence is only the local feature-installed
  signal; the module never enables the Windows optional feature or claims “no
  VM”.
- `sandbox::windows::etw` attempts a private process-provider session for
  observation. If the token cannot create or enable it, use the honest
  `ReadDirectoryChangesW` and process-handle polling fallbacks; those do not
  represent complete syscall or network telemetry.
- `sandbox::windows::minifilter` only validates an already-installed service,
  its `ImagePath` binding, a signed `.sys` image, and running state. There is
  no service/driver installation or start path. Selecting an absent,
  mismatched, or untrusted driver returns an error.
- `sandbox::windows::eventlog` opens an existing Event Log source. Registering
  a new source is an administrator-owned registry operation and is refused by
  this library.

## macOS

`sandbox/macos/net_proxy.rs` is a local broker helper. DNS is resolved on the
broker side, private/metadata/link-local/documentation/NAT64 addresses are
rejected, and each authorized connection uses the pinned `SocketAddr` without
another hostname lookup. The helper binds only to loopback and supports TLS
pass-through; it never performs TLS MITM. The current library surface does not
authenticate arbitrary local loopback clients, so the security worker must add
its own client-authenticated handoff when integrating it.

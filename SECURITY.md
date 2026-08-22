# Security policy & honest limitations

vetto's threat model: a **locally-invoked AI coding agent** (or any tool it
spawns) attempting to read secrets, exfiltrate data, or persist changes
outside the project. The operator is trusted; the agent is not. This is a
containment/visibility tool for developer machines — NOT a hardening
boundary against a hostile kernel, root, or physical access.

## Reporting

Open a private security advisory via GitHub (Security → Report a
vulnerability) for anything that lets a sandboxed agent reach files, network,
or processes the active policy denies.

## ALL honest limitations (read before relying on vetto)

1. **`sandbox-exec` is deprecated.** The macOS backend rides on Apple's
   undocumented-but-working Seatbelt runner. Apple may remove it in any
   macOS release; vetto would fail closed at that point (the agent stops
   running, it does not run unsandboxed).

2. **macOS denial visibility parity gap.** Seatbelt denials are invisible to
   FSEvents — the same enforcement-vs-observation gap as Linux. FSEvents
   (not implemented in v0.1) would show *allowed* ops with 50–200 ms latency
   even if present; blocked-attempt visibility on macOS effectively does not
   exist in v0.1. Enforcement is active regardless.

3. **Kernel audit reality.** Landlock denials surface in the audit stream
   only on kernel ≥ 6.12, and *reading* that stream requires privileges
   (auditd / `CAP_AUDIT_READ`) that an unprivileged vetto usually lacks.
   Probe at runtime; expect "unavailable"; the persistent notice and active
   enforcement are the default experience.

4. **Secret sanitizer is BEST-EFFORT.** Pattern-based redaction (AWS keys,
   GitHub/Slack/sk- tokens, PEM bodies, key=value pairs) with known false
   positives AND false negatives. It is a courtesy for shareable artifacts,
   never a guarantee, and is labeled as such everywhere it appears.

5. **FS-ONLY orphan gap.** Without user namespaces there is no PID
   namespace: cleanup is `PR_SET_PDEATHSIG` + `setpgid` + `kill(-pgid)`.
   Grandchildren that explicitly `setsid()` away from the group can survive
   vetto's death in this tier. Tier FULL's PID namespace covers them.

6. **Windows is absent from v0.1** (roadmap v0.3+; enterprise audit reports
   noted). A Windows build fails with an explicit error rather than shipping
   a non-sandboxing binary.

7. **Observation is racy by design.** The `--observe-seccomp` tap reads path
   arguments from `/proc/<pid>/mem` around a user-notify window; reported
   paths can be stale. This is acceptable *only* because the tap never
   enforces — `SECCOMP_USER_NOTIF_FLAG_CONTINUE` answers every notification
   and Landlock remains the sole filesystem enforcer.

8. **Allowed-op observation granularity.** The `/proc/<pid>/fd` poller runs
   every ~100 ms; opens shorter than that are invisible. Never treat
   "no FileObserved events" as "nothing happened".

9. **Allowlist mode is proxy-shaped.** Only HTTP(S)/socks5 CONNECT-style
   clients work (via injected proxy env). Non-proxy protocols fail closed
   (git-over-SSH does not work in allowlist mode). The domain check happens
   on the CONNECT target before TLS — there is no SNI parsing, no TLS
   decryption, and no CA injection, ever.

10. **Policy is per-machine at load time.** Globs are expanded when the
    session starts; files created later matching `$PROJECT/**/*.pem` are NOT
    retroactively denied on FS-ONLY (Tier FULL denies by allowlist
    semantics — new files outside allowed read roots stay unreadable... note
    the project root itself is writable, so new secret-shaped files created
    by the agent inside the project are only masked by shape heuristics at
    the next session's load).

11. **The agent binary itself.** vetto warns when the agent binary is inside
    a write scope (the agent could replace its own binary) — it cannot
    police binaries you point it at.

## What vetto guarantees anyway

- **Fail-closed**: if the sandbox cannot be established, the agent does not
  run. There is no unsandboxed fallback, ever.
- **Kernel enforcement**: filesystem decisions in Landlock happen in the VFS
  on the resolved inode (TOCTOU structurally impossible); namespaces/seccomp
  are kernel primitives; no root required for any of it.
- **No new attack surface**: no daemon, no sockets listening on the network,
  no elevated helper, no cloud, no telemetry.
- **Honest UX**: doctor reports exactly what is enforced and what is merely
  observed; every artifact says BEST-EFFORT where it means it.

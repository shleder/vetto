# vetto architecture

vetto is a single binary that supervises one agent session per invocation.
No daemons, no background state: everything below happens inside one process
tree per `vetto -- <agent>` run.

## Session wiring (load-bearing order)

1. **Single-threaded phase** — CLI parse, policy load (glob expansion against
   the real filesystem), PATH resolution of the agent binary, stdio plumbing
   (PTY / pipes). *Every fork in vetto happens here* — forking a
   multi-threaded process risks deadlocks on allocator locks, so the sandbox
   chains run before any thread or async runtime exists.
2. **Spawn** — the sandbox backend builds enforcement in a fork chain (below)
   and the supervisor adopts the waitable handle. Fail-closed: any setup
   failure means the agent never runs; there is no unsandboxed fallback.
3. **Threaded phase** — event-bus consumers (network broker, seccomp-notify
   watchdog, audit reader, /proc visibility poller, JSONL sink, stats
   collector) and the UI loop (statusline / dashboard / none).

## Linux Tier FULL — the fork chain

```
vetto (parent, single-threaded)
 └─fork→ S                         prctl(PDEATHSIG)+getppid check
    ├─ unshare(USER) → pid↔parent handshake → parent writes uid/gid maps
    ├─ unshare(MOUNT); mount --make-rprivate /
    ├─ unshare(IPC); unshare(NET)
    ├─ [allowlist] blackhole /etc/resolv.conf; fork→ R (relay)
    │    R: in the netns, outside the later pidns; serves 127.0.0.1:<port>
    │       HTTP CONNECT + socks5; forwards {host,port} to the broker over an
    │       inherited AF_UNIX socketpair
    ├─ unshare(PID)   (after R so R stays reachable)
    ├─ mount overlays over every resolved display_only_deny path
    │    (files: bind /dev/null; dirs: empty tmpfs mode=000) — the ONLY way
    │    to carve secrets out of an allowed tree in Landlock
    ├─ landlock restrict_self (pure allowlist; VFS/inode decisions)
    ├─ [--observe-seccomp] install user-notify tap → send listener fd to
    │    parent via SCM_RIGHTS (fail-open: observation only)
    └─fork→ B                       PID 1 of the inner pidns
        ├─fork→ C                   setsid + TIOCSCTTY (or pipe dup2s),
        │                           chdir($PROJECT), execve(agent)
        └─ loop: waitpid(-1, WNOHANG) + poll(alive pipe, 50 ms)
             C died  → remember exit code; kill(-1); reap; exit(code)
             alive pipe EOF (vetto died) → kill(-1); reap; exit
```

- Killing vetto ⇒ alive-pipe EOF ⇒ B kills the namespace ⇒ kernel reaps the
  rest. PDEATHSIG is belt-and-suspenders on every hop.
- seccomp **never** enforces paths. The user-notify tap answers every
  notification with `SECCOMP_USER_NOTIF_FLAG_CONTINUE`; Landlock stays the
  sole filesystem enforcer.

## Linux Tier FS-ONLY (no unprivileged userns)

Single fork; the child **is** the agent after: `setsid` (own pgroup) →
seccomp-BPF network block (`socket/socketpair` on `AF_INET/6` →
`EAFNOSUPPORT`) → Landlock. Without a mount namespace, intra-project secrets
cannot be overlay-masked; instead the loader enumerates the project tree at
load time (post-order, clean subtrees collapse into single rules, opaque
dirs like `.git`/`node_modules`/`target` get blanket rules) and emits
per-entry read rules that exclude secret-shaped files; write-root rules have
`READ_FILE` stripped so the whole-tree write grant cannot re-expose them.
Budget: 20 000 entries, above which vetto falls back to whole-tree read with
a LOUD warning. Honest gap: `setsid()`-detached grandchildren survive this
tier.

## Network

- `--net=off` — FULL: interface-less netns (no `lo`, no route). FS-ONLY:
  seccomp-BPF socket block. Always enforced.
- `--net=allowlist:d1,d2` — FULL only. The proxy CANNOT live inside an
  interface-less netns (no route to anything), so:
  1. pre-fork AF_UNIX socketpair: broker end in vetto, relay end inherited;
  2. R (inside the netns) brings up `lo`, listens on 127.0.0.1:47129;
  3. the child gets `HTTP(S)_PROXY`/`ALL_PROXY` env pointing there;
  4. R parses CONNECT/socks5 requests, ships `{host,port}` to the broker;
  5. the broker (outside) resolves DNS, checks the CONNECT-level domain
     allowlist (exact or subdomain), dials, and hands the data socket back
     via SCM_RIGHTS; bytes pump both ways until EOF.
  The child never resolves DNS (`/etc/resolv.conf` blackholed); non-proxy
     protocols have no route and fail closed (git-over-SSH will not work —
     documented). No TLS decryption, ever.

## Visibility model (enforcement ≠ observation)

- Enforcement is silent (kernel).
- Allowed ops: `/proc/<pid>/fd` poll every ~100 ms, best-effort, misses
  sub-100 ms opens. Never claimed as real-time interception.
- Blocked attempts, in preference order: kernel audit feed (needs ≥ 6.12 and
  privileges an unprivileged vetto usually lacks — probed, treated as
  best-effort-rare) → `--observe-seccomp` user-notify tap (unprivileged;
  paths are racy in observation only — acceptable because enforcement never
  depends on them; the notifier classifies against the policy because the
  syscall *result* is not visible to a CONTINUE responder) → persistent
  notice "enforcement ACTIVE".

## Policy pipeline

TOML profile → variable substitution (`$PROJECT`, `$HOME`, `~/`) → glob
expansion at **load time** (globs do not exist at the enforcement layer;
Landlock only understands concrete paths) → sanity warnings (system write
roots, wholesale `$HOME` reads, nonexistent write roots dropped) → tier
adjustment (FS-ONLY enumeration) → resolved `Policy` of concrete roots.

## macOS

Seatbelt profile generated from the same resolved `Policy`:
`(deny default)` + subpath allows + trailing `(deny file-read*)` carve-outs
(SBPL: last matching rule wins) + `(deny network*)` for `--net=off`, applied
via `/usr/bin/sandbox-exec`. Honest gaps (SECURITY.md): sandbox-exec is
deprecated; denials are invisible to FSEvents; no PDEATHSIG — v0.1 cleans up
only via process-group kill on normal exit.

## Repository layout

```
src/
  main.rs                 wiring, doctor (--probe), init, profiles
  cli.rs config.rs        clap CLI → RunConfig
  policy/                 types, loader, glob resolve, checker, defaults
  events/                 Event + tokio broadcast bus (sync publish)
  sandbox/
    handle.rs             spawn contract, wait/try_wait, kill strategies
    linux/                probe/tier selection, fork chains, landlock,
                          namespaces, mounts, seccomp netblock, net relay,
                          observe tap, /proc poller, audit reader
    macos/                seatbelt generation + honest stubs
  pty/                    posix_openpt pair, SIGWINCH latch, resize
  tui/                    statusline pass-through + overlay, full dashboard
  logger/                 stderr tracing, JSONL sink, BEST-EFFORT sanitizer
  report/                 stats collector, self-contained HTML/MD/JSON
tests/integration/        conditional matrix driving the compiled binary
```

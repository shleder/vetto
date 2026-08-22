# Performance notes

vetto adds two kinds of cost: one-time session setup, and per-operation
overhead while the agent runs. Numbers below are order-of-magnitude
expectations from dev builds on a commodity cloud VM (kernel 6.8); treat
them as orientation, not benchmarks.

## Session setup (one-time)
- Policy load + glob expansion: dominated by filesystem walks of `$PROJECT`;
  bounded (20 000-entry enumeration budget in FS-ONLY, 50 000-path glob cap).
  Typical projects: single-digit milliseconds.
- Tier FULL chain (userns+mounts+landlock+pidns+relay fork): ~1–3 ms.
- FS-ONLY (single fork + seccomp + landlock): < 1 ms.
- Startup is single-threaded by design (fork safety) — see ARCHITECTURE.md.

## Steady state
- **Allowed operations pay ~nothing on the enforcement path**: Landlock is a
  VFS hook evaluated per (inode, rule-set); no context switch, no broker.
  Typical agent workloads are indistinguishable from unsandboxed runs.
- **Visibility poller**: one `/proc` sweep every 100 ms on a background
  thread; cost grows with the sandboxed process count (subtree BFS + fd
  readlink per process). Event bursts are capped at 200/tick; dedup set is
  bounded at 200 k entries.
- **`--observe-seccomp`**: every trapped syscall (open*/execve*) detours to
  the notifier thread (ioctl RECV + optional `/proc/<pid>/mem` read + SEND
  CONTINUE). Expect a visible slowdown for syscall-heavy agents (compilers,
  package managers) — this is why the tap is opt-in. Without the tap there
  is zero per-syscall cost.
- **Allowlist networking**: one broker thread + a relay hop; per-connection
  setup adds a domain check + `connect()`; bulk throughput is two `copy`
  loops over unix sockets — fine for package registries and APIs, not a
  benchmark target.

## Memory
- Event ring: 1 000 events. JSONL/stats/report sinks are streaming.
- Captured output buffers (full dashboard): 512 KiB tail per stream.
- Overlay replay buffer (statusline Ctrl+]): 1 MiB cap, then honest drops.

## What to avoid
- Do not point `--jsonl` at a slow network filesystem; the sink flushes per
  line.
- Enormous monorepos can hit the FS-ONLY enumeration budget; vetto then
  falls back to whole-tree reads with a LOUD warning (prefers Tier FULL).

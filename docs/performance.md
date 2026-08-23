# Performance

vetto does not publish an unverified “less than 5%” overhead claim. Results
depend on the kernel, Landlock ABI, filesystem, process count, network path,
policy size and whether seccomp observation is enabled. Any number shown in a
release document must come from the repository benchmark suite and include
the exact revision and test environment.

## Cost model

- Policy loading and secret-glob expansion are one-time costs. They scale with
  the number of concrete paths inspected. Safety caps return an error instead
  of replacing a precise policy with a broad allow.
- Landlock is evaluated in the kernel on filesystem operations. There is no
  userspace broker on the ordinary allowed-file path.
- FULL-tier namespace, overlay and relay setup is paid once per sandbox. In
  multi-agent mode each agent intentionally pays this cost independently.
- Allowed-operation visibility walks the sandbox process tree and `/proc` file
  descriptors. Polling adapts from 50 ms while active to 500 ms after five
  idle seconds and two seconds after thirty idle seconds.
- `--observe-seccomp` adds a userspace notification round trip to observed
  syscalls and can materially slow syscall-heavy workloads. It is opt-in.
- Allowlisted network traffic makes one policy/DNS decision per connection and
  passes bytes through the loopback relay and host broker. TLS is not decoded.
- TUI rendering is event-driven and capped at five frames per second; report
  generation runs after or outside the interactive hot path.

## Reproducible measurement

Run benchmarks from an otherwise idle machine and retain raw output:

```console
cargo bench
```

The Landlock benchmark is intentionally named
`landlock-ruleset-construction-no-install`: it measures data-only rule
preparation for several concrete rule counts and does not install a sandbox
or call `restrict_self`. Visibility, seccomp observation, PTY passthrough, and
report-rendering groups likewise exercise isolated primitives; their output is
measurement data, not a product-overhead claim.

Record at least:

- git revision and whether the tree is dirty;
- `rustc -Vv` and build profile;
- OS, architecture and kernel version;
- CPU model/count and available memory;
- filesystem type and storage medium;
- detected vetto tier and Landlock ABI;
- policy/rule count, process/fd count and session event count;
- whether `--observe-seccomp`, TUI and network relay were enabled.

Compare each sandboxed scenario with the same command, data and warmed-cache
state without vetto. Report median and tail latency plus sample count; do not
promote a single run or a development build to a product claim.

## Tuning

- Leave seccomp observation disabled when blocked-attempt visibility is not
  required.
- Prefer FULL tier for large projects; FS-ONLY may need to enumerate a tree to
  preserve intra-project denials and will fail closed at its safety budget.
- Keep the project root narrow and avoid unnecessary secret glob patterns.
- Write JSONL/report artifacts to a local filesystem outside the sandbox.
- Use `--tui=none` for CI and throughput measurements.

## Publication gate

Performance targets in the mega-spec are acceptance goals, not measured facts.
They may be marked achieved only when the benchmark artifacts are reproducible
on all claimed platforms. Until then documentation must say “not yet measured”
rather than inventing a number.

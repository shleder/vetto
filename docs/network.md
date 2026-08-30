# Network modes

`vetto` starts with `--net=off`. Network enforcement is independent from the
agent's own settings and is inherited by every descendant process.

The domain relay described below is currently a Linux FULL-tier path. Linux
FS-ONLY rejects relay modes before launch. macOS Seatbelt currently supports
network-off; `--net=allowlist` is rejected and the Seatbelt spawn path does not
wire the standalone macOS broker helper. The Windows process backend currently
accepts network-off only. These platform limits are fail-closed rather than a
fallback to unrestricted networking.

## Off

```console
vetto --net=off -- agent command
```

On Linux FULL this uses an interface-less network namespace. Linux FS-ONLY
uses a seccomp filter that rejects non-Unix socket families. A backend that
cannot establish its advertised network boundary must fail before the agent
starts.

## Domain allowlist

```console
vetto --net=allowlist:api.github.com,registry.npmjs.org -- agent command
```

The sandbox has no direct route to the Internet. Proxy-aware clients send an
HTTP `CONNECT` request to a loopback relay. The relay forwards only the target
host and port over an inherited Unix socket to the host-side broker. The
broker checks the requested DNS name, resolves it once, validates every answer
and connects to one pinned `SocketAddr`. TLS bytes remain opaque: vetto does
not inspect SNI, install a CA, or decrypt traffic.

The broker rejects IP literals and DNS answers in loopback, private,
link-local, shared, multicast, documentation and reserved ranges. This covers
IPv4, IPv6, IPv4-mapped IPv6 and known NAT64 encodings, including cloud
metadata endpoints such as `169.254.169.254`.

Non-proxy-aware protocols cannot use this mode because the sandbox has no
general route. That is intentional fail-closed behaviour.

## Strict host and port rules

```console
vetto --net=strict:registry.npmjs.org:443,api.github.com:443 -- agent command
```

Strict rules use the same broker but require both a matching DNS name and the
exact configured port. A rule for `api.github.com:443` does not allow port 22.
A base-domain rule also covers its DNS subdomains; label boundaries are
checked, so `notgithub.com` does not match `github.com`.

## Interactive Ask Mode

```console
vetto --net=ask -- agent command
```

In interactive mode, any network connection attempt triggers an interactive confirmation prompt on stderr. Confirmed domains are cached in-memory for the duration of the session. If stdin is not a TTY (such as in CI or background scripts), interactive prompts fail closed and deny the connection.

## Wildcard Domains and Presets

Network rules support wildcard subdomains:
- `*.githubusercontent.com` matches `raw.githubusercontent.com` and `avatars.githubusercontent.com`, but does NOT match the base domain `githubusercontent.com`.

Policies can specify standard ecosystem presets:
```toml
[network]
net_presets = ["npm", "git", "pip", "huggingface"]
allow_cidr = ["10.0.0.0/8"]
net_quota = { "api.openai.com" = "100mb" }
```

## Landlock Net Ports (ABI 4+)

On Linux kernels with Landlock ABI 4+ (Linux 6.7+), TCP bind and connect operations can be restricted at the kernel level:
```toml
[net_ports]
allow_tcp_connect = [443, 80]
allow_tcp_bind = [8080]
```

## Unix sockets

Unix domain sockets (`AF_UNIX`) are permitted for local IPC across all network modes (including `--net=off`). In Linux seccomp filters, `AF_UNIX` socket creation and socketpairs are always permitted.

Filesystem-backed Unix sockets require explicit filesystem read/write access to the socket file and its parent directory. You can grant access via `vetto allow <path>` or configure them in policy:

```toml
[unix_sockets]
allow = ["$PROJECT/agent.sock", "/run/user/$UID/podman/podman.sock"]
```

Paths configured in `[unix_sockets] allow` are automatically granted read and write access in the filesystem sandbox.

## Upstream Proxies

The host broker respects upstream `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` environment variables without leaking proxy credentials or endpoints to the sandboxed agent.

## Git over SSH

```console
vetto --net=strict:github.com:22 --git-ssh -- git fetch origin
```

`--git-ssh` configures OpenSSH with a per-command `ProxyCommand` on Linux. The
helper uses the same broker and pumps opaque SSH bytes after an allowed
`CONNECT`. There is no persistent process. The requested host still has to be
in the network policy and the requested port has to match a strict rule. The
helper is Linux-only; other platforms fail closed if the flag is supplied.

## DNS rebinding boundary

The agent never chooses the destination IP. For each connection the broker:

1. validates the normalized requested DNS name against policy;
2. resolves it outside the sandbox;
3. rejects the whole answer set if any address is special-use or private;
4. connects directly to a validated address without resolving the hostname a
   second time.

Pinning lasts for that TCP connection. A later connection repeats all four
steps and is denied if DNS has changed to an unsafe answer.

## Diagnostics

`vetto doctor` reports the selected enforcement tier. Use `--dry-run` to see
the resolved network policy without starting the command. Connection attempts
that pass through the broker appear in JSONL and session reports; direct
attempts can be invisible when the platform's blocked-attempt observation feed
is unavailable, although enforcement remains active.

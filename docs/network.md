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

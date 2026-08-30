# Telemetry Policy and Data Dictionary

`vetto` is designed with a strict privacy-first architecture. Telemetry is completely optional and strictly disabled by default.

---

## 1. Default State: Strictly Disabled

- Telemetry is **OFF by default** (`telemetry = false`).
- If telemetry is disabled or no endpoint is configured, **zero network calls** are made.
- Telemetry can only be enabled by explicit operator configuration.

---

## 2. Configuration

To enable telemetry, configure `~/.vetto/config.toml`:

```toml
# Opt-in telemetry setting (default: false)
telemetry = true

# Custom reporting endpoint URL (default: empty / disabled)
telemetry_endpoint = "https://telemetry.your-org.internal/api/v1/sessions"
```

You can also override these settings with environment variables:
- `VETTO_TELEMETRY=true` (or `1`, `yes`, `on`)
- `VETTO_TELEMETRY_ENDPOINT=https://...`

---

## 3. What is Collected (Schema v1)

When enabled, a single anonymous JSON payload is transmitted via HTTP POST upon session termination:

```json
{
  "schema_version": 1,
  "vetto_version": "0.2.5",
  "os": "linux",
  "arch": "x86_64",
  "tier": "full",
  "session_duration_s": 42,
  "fs_denials": 3,
  "net_denials": 0,
  "total_events": 128,
  "exit_code": 0
}
```

### Data Dictionary

| Field | Type | Description |
|---|---|---|
| `schema_version` | integer | Schema version format identifier (`1`). |
| `vetto_version` | string | Installed `vetto` version (e.g. `0.2.5`). |
| `os` | string | Target operating system family (`linux`, `macos`, `windows`). |
| `arch` | string | Target CPU architecture (`x86_64`, `aarch64`). |
| `tier` | string | Activated sandbox tier (`full`, `fs-only`, `macos-seatbelt`, `windows-appcontainer`). |
| `session_duration_s` | integer | Wall-clock session runtime in seconds. |
| `fs_denials` | integer | Total aggregate count of blocked filesystem attempts. |
| `net_denials` | integer | Total aggregate count of blocked network connection attempts. |
| `total_events` | integer | Total event count captured during the session. |
| `exit_code` | integer | Exit code returned by the sandboxed process. |

---

## 4. What is NEVER Collected

Under no circumstances will `vetto` collect or transmit:
- ❌ **No File Paths or Names**: File paths, directory names, or glob patterns.
- ❌ **No File Contents**: File contents, code diffs, or repository contents.
- ❌ **No Domains or URLs**: Network domains, target hostnames, URLs, or external IPs.
- ❌ **No Command Lines**: Executable names, arguments, stdin/stdout data, or shell commands.
- ❌ **No Secrets or Tokens**: API keys, credentials, tokens, or environment variables.
- ❌ **No Identifiers**: Usernames, hostnames, machine IDs, MAC addresses, or client IP addresses.

---

## 5. Verification

You can verify that zero network activity occurs when telemetry is off by running `vetto` with standard network inspection tools (e.g. `tcpdump` or `strace`):

```bash
# Verify no network packets are sent with default configuration
vetto -- /bin/echo "testing privacy"
```

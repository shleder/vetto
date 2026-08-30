# Remote Execution & Multiplexer Architecture (`vetto serve`)

Vetto provides a background multiplexer daemon and REST API that enables local AI agents to execute code sandboxed on remote build servers or isolated virtual machines.

---

## 1. Starting Remote Server (`vetto serve`)

On the remote execution host, start Vetto in serve mode:

```bash
vetto serve --port 54321
```

This starts:
- **Loopback REST API**: `http://127.0.0.1:54321` (authenticated by Bearer token in `~/.vetto/daemon/token`).
- **Unix Domain Socket**: `~/.vetto/daemon/vetto.sock` (authenticated via `SO_PEERCRED`).

---

## 2. Forwarding over SSH

Forward the daemon endpoint to your local development machine:

```bash
# Forward REST API over SSH
ssh -R 54321:127.0.0.1:54321 user@remote-box

# Or forward the Unix domain socket (Linux / macOS)
ssh -R /tmp/vetto-remote.sock:$HOME/.vetto/daemon/vetto.sock user@remote-box
```

---

## 3. Invoking from Local Agent

On your local machine:

```bash
export VETTO_REMOTE_TOKEN="<token from remote-box ~/.vetto/daemon/token>"
vetto --remote http://127.0.0.1:54321 -- cargo test
```

Vetto submits the task to the remote server, executes it inside the remote kernel sandbox, and reports the status and exit codes back to your local terminal.

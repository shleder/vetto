# Vetto Multiplexer Daemon and REST API

Vetto includes a lightweight, headless daemon mode designed for multiplexing concurrent sandboxes and orchestrating agent execution over loopback REST API or Unix domain socket.

## Architecture

1. **Multiplexing Engine**: A single daemon process supervises multiple concurrent, completely isolated sandbox sessions via `SessionRegistry`.
2. **Dual IPC Surface**:
   - **Unix Domain Socket** (`~/.vetto/daemon/vetto.sock`) with mandatory kernel-level `SO_PEERCRED` UID authentication.
   - **Loopback REST API** (`http://127.0.0.1:54321`) with random 256-bit Bearer token authentication (`~/.vetto/daemon/token`).
3. **Remote Execution**: Clients connect via `vetto --remote <url> -- <agent>` across SSH reverse tunnels or local networks.

## CLI Usage

### Starting the Daemon

```bash
# Start daemon in background
vetto daemon start

# Start daemon on custom port in foreground
vetto daemon start --port 54321 --foreground

# Query daemon status and active sessions
vetto daemon status

# Stop daemon
vetto daemon stop
```

### Remote Sandboxing (`vetto serve` & `vetto --remote`)

```bash
# On the sandboxing host:
vetto serve --port 54321

# Forward port over SSH from remote agent box:
ssh -R 54321:127.0.0.1:54321 user@agent-machine

# On agent machine:
export VETTO_REMOTE_TOKEN="<token from ~/.vetto/daemon/token>"
vetto --remote http://127.0.0.1:54321 -- cargo test
```

## REST API Endpoints

All endpoints require `Authorization: Bearer <token>`.

### `POST /sessions`
Start a new sandboxed execution.
- **Request Body**:
  ```json
  {
    "command": ["npm", "test"],
    "policy_preset": "node",
    "net": "allowlist:registry.npmjs.org",
    "cwd": "/workspace"
  }
  ```
- **Response**: `200 OK`
  ```json
  {
    "id": "sess-a1b2c3d4",
    "status": "running",
    "created_at": "2026-09-22T18:00:00Z"
  }
  ```

### `GET /sessions`
List all active and recent sessions.

### `GET /sessions/{id}`
Inspect status, resource usage, and audit summary of a single session.

### `DELETE /sessions/{id}`
Terminate a running sandboxed session.

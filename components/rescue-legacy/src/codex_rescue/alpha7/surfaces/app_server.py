from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from codex_rescue.alpha7.graph import SurfaceObservation, SurfaceVisibility


@dataclass
class AppServerCapabilities:
    protocol_version: str = "v2"
    supported_methods: List[str] = field(
        default_factory=lambda: ["initialize", "initialized", "thread/list", "thread/read"]
    )
    server_version: Optional[str] = None
    server_pid: Optional[int] = None
    user_agent: Optional[str] = None
    codex_home: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "protocol_version": self.protocol_version,
            "supported_methods": self.supported_methods,
            "server_version": self.server_version,
            "server_pid": self.server_pid,
            "user_agent": self.user_agent,
            "codex_home": self.codex_home,
        }


class JsonRpcError(Exception):
    def __init__(self, code: int, message: str, data: Any = None):
        super().__init__(f"App Server RPC Error {code}: {message}")
        self.code = code
        self.message = message
        self.data = data


class StdioJsonRpcClient:
    """Production-grade Stdio JSON-RPC protocol client for Codex App Server.
    
    Features:
    - Matches real Codex App Server wire format (newline-delimited JSON, camelCase, omitted jsonrpc header).
    - Asynchronous reader thread handling interleaved responses, notifications, and server requests.
    - Thread-safe request/response ID correlation with timeout guards.
    - Robust process exit, EOF, and error handling.
    """

    def __init__(self, process: subprocess.Popen, timeout: float = 5.0):
        self.process = process
        self.timeout = timeout
        self._request_id = 0
        self._lock = threading.Lock()
        self._pending_responses: Dict[int, Dict[str, Any]] = {}
        self._pending_events: Dict[int, threading.Event] = {}
        self._notifications: List[Dict[str, Any]] = []
        self._server_requests: List[Dict[str, Any]] = []
        self._protocol_errors: List[Dict[str, Any]] = []
        self._running = True
        self.is_initialized = False

        # Launch background reader loop
        self._reader_thread = threading.Thread(target=self._reader_loop, daemon=True, name="CodexAppServerReader")
        self._reader_thread.start()

    def _reader_loop(self) -> None:
        """Background thread continually decoding incoming messages and routing by exact RPC classification."""
        try:
            while self._running:
                if not self.process.stdout:
                    break
                line = self.process.stdout.readline()
                if not line:
                    break
                if isinstance(line, bytes):
                    line_str = line.decode("utf-8", errors="replace").strip()
                else:
                    line_str = line.strip()

                if not line_str:
                    continue

                try:
                    msg = json.loads(line_str)
                except Exception as e:
                    with self._lock:
                        self._protocol_errors.append({"raw_line": line_str, "decode_error": str(e)})
                    continue

                if not isinstance(msg, dict):
                    with self._lock:
                        self._protocol_errors.append({"raw_line": line_str, "error": "Message is not a JSON object"})
                    continue

                has_method = "method" in msg
                has_id = ("id" in msg) and (msg["id"] is not None)
                has_result_or_error = ("result" in msg) or ("error" in msg)

                # 1. SERVER_REQUEST: has both method and id
                if has_method and has_id:
                    req_id = msg["id"]
                    with self._lock:
                        self._server_requests.append(msg)
                    # Reply with method not supported to avoid server hanging
                    err_reply = json.dumps({
                        "id": req_id,
                        "error": {
                            "code": -32601,
                            "message": f"Server request method '{msg['method']}' not supported on read-only client",
                        }
                    }) + "\n"
                    try:
                        self._write_stdin(err_reply)
                    except Exception:
                        pass

                # 2. NOTIFICATION: has method but no id
                elif has_method:
                    with self._lock:
                        self._notifications.append(msg)

                # 3. RESPONSE: has id and result/error
                elif has_id and has_result_or_error:
                    req_id = msg["id"]
                    with self._lock:
                        self._pending_responses[req_id] = msg
                        if req_id in self._pending_events:
                            self._pending_events[req_id].set()

                # 4. PROTOCOL_ERROR: unrecognized format
                else:
                    with self._lock:
                        self._protocol_errors.append(msg)
        finally:
            self._running = False
            # Unblock any waiting callers on process termination/EOF
            with self._lock:
                for evt in self._pending_events.values():
                    evt.set()

    def _write_stdin(self, msg_str: str) -> None:
        if not self.process.stdin:
            raise RuntimeError("Process stdin is closed")
        try:
            if hasattr(self.process.stdin, "buffer"):
                self.process.stdin.buffer.write(msg_str.encode("utf-8"))
                self.process.stdin.buffer.flush()
            else:
                try:
                    self.process.stdin.write(msg_str.encode("utf-8"))  # type: ignore
                except TypeError:
                    self.process.stdin.write(msg_str)
                self.process.stdin.flush()
        except (BrokenPipeError, OSError) as e:
            raise RuntimeError(f"Failed to write to app server stdin: {e}")

    def send_request(self, method: str, params: Optional[Dict[str, Any]] = None, timeout: Optional[float] = None) -> Dict[str, Any]:
        """Sends a method call and blocks until matching response ID arrives or timeout expires."""
        if self.process.poll() is not None and not self._running:
            raise RuntimeError(f"App server process terminated with code {self.process.returncode}")

        wait_sec = timeout if timeout is not None else self.timeout
        evt = threading.Event()

        with self._lock:
            self._request_id += 1
            req_id = self._request_id
            self._pending_events[req_id] = evt
            payload = {
                "id": req_id,
                "method": method,
                "params": params if params is not None else {},
            }

        msg = json.dumps(payload) + "\n"
        self._write_stdin(msg)

        # Wait for correlated response
        signaled = evt.wait(timeout=wait_sec)
        with self._lock:
            resp = self._pending_responses.pop(req_id, None)
            self._pending_events.pop(req_id, None)

        if not signaled or resp is None:
            if self.process.poll() is not None:
                raise RuntimeError(f"App server exited with code {self.process.returncode} while awaiting response to {method}")
            raise TimeoutError(f"App server request '{method}' (id={req_id}) timed out after {wait_sec}s")

        if "error" in resp and resp["error"]:
            err = resp["error"]
            if isinstance(err, dict):
                raise JsonRpcError(
                    code=err.get("code", -32000),
                    message=err.get("message", "Unknown error"),
                    data=err.get("data"),
                )
            raise JsonRpcError(code=-32000, message=str(err))

        return resp.get("result", {})

    def send_notification(self, method: str, params: Optional[Dict[str, Any]] = None) -> None:
        """Sends a one-way notification to the server without expecting a response."""
        if self.process.poll() is not None:
            return

        payload: Dict[str, Any] = {"method": method}
        if params is not None:
            payload["params"] = params

        msg = json.dumps(payload) + "\n"
        try:
            self._write_stdin(msg)
        except Exception:
            pass

    def get_notifications(self) -> List[Dict[str, Any]]:
        with self._lock:
            notifs = list(self._notifications)
            self._notifications.clear()
            return notifs

    def get_server_requests(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._server_requests)

    def get_protocol_errors(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._protocol_errors)

    def close(self) -> None:
        """Stops the reader thread and shuts down stdio."""
        self._running = False
        try:
            if self.process.stdin:
                self.process.stdin.close()
        except Exception:
            pass


class RealAppServerClient:
    """Production-grade App Server protocol client supporting stdio lifecycle."""

    def __init__(self, codex_home: Optional[Path] = None, timeout: float = 5.0):
        self.codex_home = codex_home or Path(os.environ.get("CODEX_HOME", Path.home() / ".codex"))
        self.timeout = timeout
        self._client: Optional[StdioJsonRpcClient] = None
        self._process: Optional[subprocess.Popen] = None
        self.capabilities = AppServerCapabilities()

    def launch_stdio_server(self, binary_path: Optional[str] = None) -> bool:
        """Launches real `codex app-server --stdio` subprocess communicating over stdio."""
        codex_bin = binary_path or os.environ.get("CODEX_BIN") or shutil.which("codex")
        if not codex_bin:
            return False

        cmd = [codex_bin, "app-server", "--stdio"]
        env = os.environ.copy()
        env["CODEX_HOME"] = str(self.codex_home)

        try:
            self._process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                shell=(os.name == "nt" and codex_bin.endswith(".ps1")),
            )
            self._client = StdioJsonRpcClient(self._process, timeout=self.timeout)
            return True
        except FileNotFoundError:
            return False
        except Exception:
            return False

    def connect_existing_client(self, client: StdioJsonRpcClient) -> None:
        """Connects a pre-spawned transport client."""
        self._client = client

    def initialize(self) -> Dict[str, Any]:
        """Performs real Codex initialize -> initialized handshake."""
        if not self._client:
            raise RuntimeError("App server transport not connected")

        res = self._client.send_request(
            "initialize",
            {
                "clientInfo": {
                    "name": "codex_rescue",
                    "title": "Codex Rescue",
                    "version": "0.7.0",
                },
                "capabilities": {
                    "experimentalApi": False,
                },
            },
        )
        self._client.send_notification("initialized")
        self._client.is_initialized = True

        if isinstance(res, dict):
            self.capabilities.user_agent = res.get("userAgent")
            self.capabilities.codex_home = res.get("codexHome")
        return res

    def list_threads(self, limit: int = 50, archived: Optional[bool] = None) -> List[Dict[str, Any]]:
        """Invokes real `thread/list` method."""
        if not self._client or not self._client.is_initialized:
            raise RuntimeError("App server not initialized")

        params: Dict[str, Any] = {"limit": limit}
        if archived is not None:
            params["archived"] = archived

        res = self._client.send_request("thread/list", params)
        if isinstance(res, dict) and "data" in res:
            return res["data"]
        elif isinstance(res, list):
            return res
        return []

    def read_thread(self, thread_id: str, include_turns: bool = False) -> Optional[Dict[str, Any]]:
        """Invokes real `thread/read` method with camelCase `threadId` parameter."""
        if not self._client or not self._client.is_initialized:
            raise RuntimeError("App server not initialized")

        try:
            res = self._client.send_request(
                "thread/read",
                {
                    "threadId": thread_id,
                    "includeTurns": include_turns,
                },
            )
            return res if isinstance(res, dict) else None
        except JsonRpcError as e:
            # Keep -32600/-32602 swallowed as "not a thread I can identify here".
            # Let 404 and -32601 propagate so the adapter can classify them as
            # COMPACTION_NOT_SUPPORTED instead of silently reporting NOT_FOUND.
            if e.code in (-32600, -32602):
                return None
            raise

    def shutdown(self) -> None:
        """Clean shutdown of client, pipes, and subprocess."""
        if self._client:
            self._client.close()

        if self._process:
            try:
                self._process.terminate()
                self._process.wait(timeout=2.0)
            except Exception:
                try:
                    self._process.kill()
                    self._process.wait(timeout=1.0)
                except Exception:
                    pass
            self._process = None
        self._client = None


@dataclass
class ServerProbeResult:
    reachable: bool = False
    has_binary: bool = False
    binary_path: Optional[str] = None
    status: str = "OFFLINE"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "reachable": self.reachable,
            "has_binary": self.has_binary,
            "binary_path": self.binary_path,
            "status": self.status,
        }


class AppServerAdapter:
    """Read-only adapter for App Server surface discovery and thread visibility."""

    def __init__(self, codex_home: Optional[Path] = None):
        self.codex_home = codex_home or Path(os.environ.get("CODEX_HOME", Path.home() / ".codex"))

    def observe_thread(self, session_id: str, client: Optional[RealAppServerClient] = None) -> SurfaceObservation:
        """Probes thread visibility through real App Server client or honest fallback."""
        if client and client._client and client._client.is_initialized:
            try:
                thread_data = client.read_thread(session_id)
                if thread_data is not None:
                    return SurfaceObservation(
                        surface="app_server",
                        visibility=SurfaceVisibility.VISIBLE,
                        notes="Thread verified readable via Codex App Server protocol",
                    )
                return SurfaceObservation(
                    surface="app_server",
                    visibility=SurfaceVisibility.HIDDEN,
                    error_code="NOT_FOUND",
                    notes="Thread not found in App Server store",
                )
            except JsonRpcError as e:
                err_code = "COMPACTION_NOT_SUPPORTED" if e.code in (-32601, 404) else "ENDPOINT_UNAVAILABLE"
                return SurfaceObservation(
                    surface="app_server",
                    visibility=SurfaceVisibility.UNSUPPORTED,
                    error_code=err_code,
                    notes=f"App server RPC returned {e.code}: {e.message}",
                )
            except (TimeoutError, OSError) as e:
                return SurfaceObservation(
                    surface="app_server",
                    visibility=SurfaceVisibility.UNSUPPORTED,
                    error_code="ENDPOINT_UNAVAILABLE",
                    notes=str(e),
                )
            except Exception as e:
                return SurfaceObservation(
                    surface="app_server",
                    visibility=SurfaceVisibility.INACCESSIBLE,
                    error_code="ENDPOINT_UNAVAILABLE",
                    notes=str(e),
                )

        return SurfaceObservation(
            surface="app_server",
            visibility=SurfaceVisibility.UNSUPPORTED,
            error_code="SERVER_OFFLINE",
            notes="No active Codex App Server attached",
        )

    def probe_server(self) -> ServerProbeResult:
        """Probes local App Server presence and connectivity."""
        codex_bin = os.environ.get("CODEX_BIN") or shutil.which("codex")
        has_bin = codex_bin is not None
        return ServerProbeResult(
            reachable=False,
            has_binary=has_bin,
            binary_path=str(codex_bin) if has_bin else None,
            status="OFFLINE",
        )

from __future__ import annotations

import argparse
import hashlib
import json
import os
import queue
import re
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _terminate_owned_tree(proc: subprocess.Popen[str]) -> None:
    if proc.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    if proc.poll() is None:
        proc.kill()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--executable", required=True, type=Path)
    parser.add_argument("--node-script", type=Path)
    parser.add_argument("--codex-home", required=True, type=Path)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--marker-regex", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=90)
    parser.add_argument("codex_args", nargs=argparse.REMAINDER)
    args = parser.parse_args()

    executable = args.executable.resolve(strict=True)
    repo = args.repo.resolve(strict=True)
    codex_home = args.codex_home.resolve()
    output = args.output_dir.resolve()
    codex_home.mkdir(parents=True, exist_ok=True)
    output.mkdir(parents=True, exist_ok=True)
    command = [str(executable)]
    if args.node_script:
        command.append(str(args.node_script.resolve(strict=True)))
    forwarded = args.codex_args[1:] if args.codex_args[:1] == ["--"] else args.codex_args
    command.extend(forwarded)
    env = os.environ.copy()
    env["CODEX_HOME"] = str(codex_home)
    stdout_path, stderr_path = output / "stdout.jsonl", output / "stderr.txt"
    started = datetime.now(timezone.utc)
    proc = subprocess.Popen(
        command, cwd=repo, env=env, text=True, encoding="utf-8", errors="replace",
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=1,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
    )
    events: queue.Queue[tuple[str, str | None]] = queue.Queue()

    def read_stream(name: str, stream: object) -> None:
        try:
            for line in stream:  # type: ignore[union-attr]
                events.put((name, line.rstrip("\r\n")))
        finally:
            events.put((name, None))

    threads = [
        threading.Thread(target=read_stream, args=("stdout", proc.stdout), daemon=True),
        threading.Thread(target=read_stream, args=("stderr", proc.stderr), daemon=True),
    ]
    for thread in threads:
        thread.start()
    marker = re.compile(args.marker_regex)
    marker_line: str | None = None
    termination = "child_exit"
    deadline = time.monotonic() + args.timeout_seconds
    closed: set[str] = set()
    with stdout_path.open("w", encoding="utf-8", newline="\n") as out, stderr_path.open("w", encoding="utf-8", newline="\n") as err:
        while len(closed) < 2 or proc.poll() is None:
            try:
                name, line = events.get(timeout=0.05)
            except queue.Empty:
                name = ""
                line = ""
            if line is None:
                closed.add(name)
            elif name:
                target = out if name == "stdout" else err
                target.write(line + "\n")
                target.flush()
                if marker_line is None and marker.search(line):
                    marker_line = line
            if marker_line is not None and proc.poll() is None:
                termination = "marker"
                _terminate_owned_tree(proc)
            elif time.monotonic() >= deadline and proc.poll() is None:
                termination = "timeout"
                _terminate_owned_tree(proc)
            if proc.poll() is not None and len(closed) == 2:
                break
        proc.wait(timeout=10)
    for thread in threads:
        thread.join(timeout=2)
    meta = {
        "schema_version": 1,
        "executable": str(executable), "codex_home": str(codex_home), "repo": str(repo),
        "pid": proc.pid, "arguments": forwarded, "started_at": started.isoformat(),
        "finished_at": datetime.now(timezone.utc).isoformat(), "termination": termination,
        "marker_seen": marker_line is not None,
        "marker_line_sha256": hashlib.sha256(marker_line.encode()).hexdigest() if marker_line else None,
        "child_exit_code": proc.returncode,
        "hashes": {stdout_path.name: _sha256(stdout_path), stderr_path.name: _sha256(stderr_path)},
    }
    (output / "metadata.json").write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0 if termination == "marker" else (3 if termination == "timeout" else 4)


if __name__ == "__main__":
    raise SystemExit(main())

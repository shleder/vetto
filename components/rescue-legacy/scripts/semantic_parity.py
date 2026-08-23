from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


def _run(command: list[str]) -> dict[str, Any]:
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    return json.loads(result.stdout)


def _smoke_rollout(directory: Path) -> Path:
    path = directory / "alpha5-smoke.jsonl"
    records = [
        {"type": "session_meta", "payload": {"id": "alpha5-smoke"}},
        {"type": "event_msg", "payload": {"type": "user_message", "message": "smoke"}},
        {"type": "response_item", "payload": {"type": "message", "id": "msg_smoke", "role": "assistant", "content": []}},
    ]
    path.write_text("".join(json.dumps(item, separators=(",", ":")) + "\n" for item in records), encoding="utf-8")
    return path


def _compare(reference: dict[str, Any], candidate: dict[str, Any], label: str) -> None:
    if reference != candidate:
        raise SystemExit(
            f"structured JSON semantic parity failed for {label}\n"
            f"python={json.dumps(reference, sort_keys=True)}\n"
            f"candidate={json.dumps(candidate, sort_keys=True)}"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--native", required=True, type=Path)
    parser.add_argument("--node-launcher", type=Path)
    parser.add_argument("--output-dir", type=Path, default=Path("build/parity"))
    args = parser.parse_args()

    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as directory:
        rollout = _smoke_rollout(Path(directory))
        common = ["doctor", str(rollout), "--json"]
        python_result = _run([sys.executable, "-m", "codex_rescue.cli", *common])
        native_result = _run([str(args.native.resolve()), *common])
        _compare(python_result, native_result, "native executable")
        (output / "python.json").write_text(json.dumps(python_result, indent=2, sort_keys=True), encoding="utf-8")
        (output / "native.json").write_text(json.dumps(native_result, indent=2, sort_keys=True), encoding="utf-8")

        if args.node_launcher:
            npm_result = _run(["node", str(args.node_launcher.resolve()), *common])
            _compare(python_result, npm_result, "npm wrapper")
            (output / "npm.json").write_text(json.dumps(npm_result, indent=2, sort_keys=True), encoding="utf-8")
    print("structured JSON semantic parity: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

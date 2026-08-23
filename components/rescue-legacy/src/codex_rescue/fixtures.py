from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


def _line(record: dict[str, Any]) -> bytes:
    return json.dumps(record, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


def _remove_readonly(func: Any, path: str, _excinfo: Any) -> None:
    os.chmod(path, stat.S_IWRITE)
    func(path)


def _remove_git_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path, onerror=_remove_readonly)


def _hash_tree_files(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for file in sorted(item for item in path.rglob("*") if item.is_file()):
        if ".git" in file.parts:
            continue
        result[str(file.relative_to(path)).replace("\\", "/")] = hashlib.sha256(file.read_bytes()).hexdigest()
    return result


@contextmanager
def materialize_fixture_git_repo(fixture: Path) -> Iterator[Path]:
    repo_before = fixture / "repo_before"
    repo_actual = fixture / "repo_actual"

    assert repo_before.exists(), f"repo_before missing in {fixture}"
    assert repo_actual.exists(), f"repo_actual missing in {fixture}"
    assert not (repo_before / ".git").exists(), f"repo_before contains .git in {fixture}"
    assert not (repo_actual / ".git").exists(), f"repo_actual contains .git in {fixture}"

    actual_before_hashes = _hash_tree_files(repo_actual)

    with tempfile.TemporaryDirectory(prefix="fixture-git-") as td:
        baseline = Path(td) / "baseline"
        shutil.copytree(repo_before, baseline)

        _git(baseline, "init", "-q")
        _git(baseline, "config", "user.name", "Codex Rescue Fixture")
        _git(baseline, "config", "user.email", "fixture@example.invalid")
        _git(baseline, "config", "core.autocrlf", "false")
        _git(baseline, "add", "-A")

        env = os.environ.copy()
        env["GIT_AUTHOR_DATE"] = "2026-01-01T00:00:00Z"
        env["GIT_COMMITTER_DATE"] = "2026-01-01T00:00:00Z"

        subprocess.run(["git", "commit", "-qm", "fixture baseline"], cwd=baseline, env=env, check=True, capture_output=True)

        git_dst = repo_actual / ".git"
        # Git may create and remove maintenance locks while the repository is
        # being copied.  They are transient state, not part of the fixture,
        # so ignore them to avoid a cross-platform copy race.
        shutil.copytree(baseline / ".git", git_dst, ignore=shutil.ignore_patterns("*.lock"))

        try:
            yield repo_actual
        finally:
            _remove_git_dir(git_dst)
            actual_after_hashes = _hash_tree_files(repo_actual)
            assert actual_after_hashes == actual_before_hashes, f"repo_actual files mutated in {fixture}"


def _base_repo(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    _git(path, "init", "-q")
    _git(path, "config", "user.email", "fixture@example.com")
    _git(path, "config", "user.name", "Fixture")
    (path / "app.txt").write_text("base\n", encoding="utf-8")
    _git(path, "add", "app.txt")
    _git(path, "commit", "-qm", "base")


def _meta(session_id: str, cwd: Path) -> dict[str, Any]:
    return {
        "timestamp": "2026-08-12T00:00:00Z",
        "type": "session_meta",
        "payload": {"id": session_id, "session_id": session_id, "cwd": cwd.as_posix(), "cli_version": "0.147.0"},
    }


def generate_fixtures(root: str | Path) -> None:
    root = Path(root)
    if root.exists():
        shutil.rmtree(root, onerror=_remove_readonly)
    root.mkdir(parents=True)

    specs: list[tuple[str, str]] = [
        ("kill_apply_patch", "UNFINISHED_TOOL_CALL"),
        ("kill_shell_before_result", "UNFINISHED_TOOL_CALL"),
        ("oversized_payload", "OVERSIZED_PAYLOAD"),
        ("malformed_jsonl", "MALFORMED_RECORD"),
        ("lost_tail_after_compaction", "COMPACTION_STATE_LOSS"),
    ]
    for name, expected in specs:
        fixture = root / name
        repo_before = fixture / "repo_before"
        repo_actual = fixture / "repo_actual"
        source_dir = fixture / "source_session"
        _base_repo(repo_before)
        shutil.copytree(repo_before, repo_actual)
        source_dir.mkdir(parents=True)
        session_id = f"fixture-{name}"
        session = source_dir / f"rollout-{session_id}.jsonl"
        records = [
            _meta(session_id, repo_actual),
            {"timestamp": "2026-08-12T00:00:01Z", "type": "event_msg", "payload": {"type": "user_message", "message": f"fixture {name}"}},
        ]
        raw = b"".join(_line(record) for record in records)

        if name == "kill_apply_patch":
            (repo_actual / "app.txt").write_text("base\npartial patch\n", encoding="utf-8")
            raw += _line({"type": "response_item", "payload": {"type": "function_call", "name": "apply_patch", "call_id": "call-patch", "arguments": "*** Begin Patch"}})
        elif name == "kill_shell_before_result":
            (repo_actual / "generated.txt").write_text("side effect exists\n", encoding="utf-8")
            raw += _line({"type": "response_item", "payload": {"type": "function_call", "name": "shell_command", "call_id": "call-shell", "arguments": json.dumps({"command": "python script.py"})}})
        elif name == "oversized_payload":
            raw += _line({"type": "response_item", "payload": {"type": "input_image", "image_url": "data:image/png;base64," + ("A" * 1_200_000)}})
            raw += _line({"type": "event_msg", "payload": {"type": "agent_message", "message": "continue with app.txt"}})
        elif name == "malformed_jsonl":
            raw += _line({"type": "event_msg", "payload": {"type": "agent_message", "message": "valid prefix"}})
            raw += b'{"type":"response_item","payload":{"type":"function_call","arguments":"bad\x00'
        elif name == "lost_tail_after_compaction":
            (repo_actual / "app.txt").write_text("base\nverified post-compact edit\n", encoding="utf-8")
            raw += _line({"type": "response_item", "payload": {"type": "function_call", "name": "shell_command", "call_id": "test-1", "arguments": json.dumps({"command": "pytest"})}})
            raw += _line({"type": "response_item", "payload": {"type": "function_call_output", "call_id": "test-1", "output": {"exit_code": 0, "command": "pytest"}}})
            raw += _line({"type": "compacted", "payload": {"message": "generic summary without operational tail", "replacement_history": [], "window_number": 1, "window_id": "w1"}})

        session.write_bytes(raw)
        # repo_before is a harness-only reference snapshot; it is not a
        # durable pre-salvage baseline in the handoff.  The verifier therefore
        # must not infer repository divergence from repo_before/repo_actual.
        # Unknown execution or transcript state is REVIEW_REQUIRED instead.
        (fixture / "expected.json").write_text(
            json.dumps({"doctor": expected, "verify": "REVIEW_REQUIRED"}, indent=2) + "\n",
            encoding="utf-8",
        )
        (fixture / "README.md").write_text(
            f"# {name}\n\nSynthetic fixture matching the Codex 0.147.0 JSONL envelope. Expected primary class: `{expected}`.\n",
            encoding="utf-8",
        )

        # Remove .git directories so generated fixtures are plain snapshots
        _remove_git_dir(repo_before / ".git")
        _remove_git_dir(repo_actual / ".git")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    generate_fixtures(parser.parse_args().root)

from __future__ import annotations

import json
import sys
import subprocess
import tempfile
import unittest
from pathlib import Path


class ControllerScriptTests(unittest.TestCase):
    def test_marker_terminates_owned_child_and_writes_evidence(self) -> None:
        root = Path(__file__).resolve().parents[1]
        script = root / "scripts" / "run_interrupted_case.py"
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            repo, home, output = base / "repo", base / "home", base / "out"
            repo.mkdir()
            child = base / "fake_child.py"
            child.write_text(
                "import json, time\n"
                "print(json.dumps({'type':'thread.started'}), flush=True)\n"
                "print(json.dumps({'type':'tool_call','command':'Start-Sleep -Seconds 120'}), flush=True)\n"
                "time.sleep(120)\n",
                encoding="utf-8",
            )
            command = [
                sys.executable, str(script), "--executable", sys.executable, "--codex-home", str(home),
                "--repo", str(repo), "--output-dir", str(output), "--marker-regex", "Start-Sleep",
                "--timeout-seconds", "10", "--", str(child),
            ]
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            metadata = json.loads((output / "metadata.json").read_text(encoding="utf-8"))
            self.assertTrue(metadata["marker_seen"])
            self.assertEqual(metadata["termination"], "marker")
            self.assertIn("Start-Sleep", (output / "stdout.jsonl").read_text(encoding="utf-8"))
            self.assertIn("stdout.jsonl", metadata["hashes"])


if __name__ == "__main__":
    unittest.main()

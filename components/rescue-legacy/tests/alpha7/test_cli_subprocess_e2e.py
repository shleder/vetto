from __future__ import annotations

import contextlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

SRC_DIR = str(Path(__file__).resolve().parent.parent.parent / "src")


@contextlib.contextmanager
def safe_temp_codex_home():
    td = tempfile.mkdtemp()
    try:
        yield Path(td)
    finally:
        if os.name == "nt":
            time.sleep(0.2)
        shutil.rmtree(td, ignore_errors=True)


class CliSubprocessE2ETests(unittest.TestCase):
    def _make_env(self, chome: Path) -> dict:
        env = os.environ.copy()
        env["CODEX_HOME"] = str(chome)
        pp = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = f"{SRC_DIR}{os.pathsep}{pp}" if pp else SRC_DIR
        return env

    def test_cli_auto_no_args_subprocess(self):
        with safe_temp_codex_home() as chome:
            env = self._make_env(chome)

            cmd = [sys.executable, "-m", "codex_rescue", "auto", "--json", "--codex-home", str(chome)]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                env=env,
                timeout=5.0,
            )
            self.assertEqual(proc.returncode, 0, f"Stderr: {proc.stderr}")
            data = json.loads(proc.stdout)
            self.assertEqual(data["data"]["action_taken"], "INSPECTED")

    def test_cli_auto_surface_flag_explicit(self):
        with safe_temp_codex_home() as chome:
            env = self._make_env(chome)

            for surf in ["cli", "desktop", "ide", "all"]:
                cmd = [
                    sys.executable,
                    "-m",
                    "codex_rescue",
                    "auto",
                    "--surface",
                    surf,
                    "--json",
                    "--codex-home",
                    str(chome),
                ]
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    env=env,
                    timeout=5.0,
                )
                self.assertEqual(proc.returncode, 0, f"Stderr for {surf}: {proc.stderr}")
                data = json.loads(proc.stdout)
                self.assertEqual(data["data"]["selected_surface"], surf)

    def test_cli_self_test_subprocess(self):
        with safe_temp_codex_home() as chome:
            env = self._make_env(chome)
            cmd = [sys.executable, "-m", "codex_rescue", "self-test", "--json", "--codex-home", str(chome)]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                env=env,
                timeout=5.0,
            )
            self.assertEqual(proc.returncode, 0, f"Stderr: {proc.stderr}")
            data = json.loads(proc.stdout)
            self.assertIn(data["data"]["overall_status"], ("PASS", "LIMITED"))

    def test_cli_interactive_surface_selector_simulated(self):
        with safe_temp_codex_home() as chome:
            env = self._make_env(chome)
            sdir = chome / "sessions"
            sdir.mkdir(parents=True)
            # Create session to have CLI surface
            (sdir / "s1.jsonl").write_text('{"turn":1}\n', encoding="utf-8")
            # Create state.db to have Desktop surface
            state_db = chome / "state.db"
            state_db.write_text("", encoding="utf-8")

            # Pass "1\n" via stdin to select CLI
            cmd = [sys.executable, "-m", "codex_rescue", "auto", "--codex-home", str(chome)]
            proc = subprocess.run(
                cmd,
                input="1\n",
                capture_output=True,
                text=True,
                env=env,
                timeout=5.0,
            )
            self.assertEqual(proc.returncode, 0, f"Stderr: {proc.stderr}")
            self.assertIn("Autopilot", proc.stdout)

    def test_cli_repair_safe_subprocess(self):
        import sqlite3

        with safe_temp_codex_home() as chome:
            env = self._make_env(chome)
            sdir = chome / "sessions"
            sdir.mkdir(parents=True)
            sess = sdir / "rollout-2026-08-19T12-00-00-11111111-2222-3333-4444-555555555555.jsonl"
            sess.write_text('{"turn":1, "prompt": "repair me"}\n', encoding="utf-8")

            # Create valid state_5.sqlite with threads table
            state_db = chome / "state_5.sqlite"
            conn = sqlite3.connect(str(state_db))
            conn.execute("PRAGMA user_version = 5")
            conn.execute(
                """
                CREATE TABLE threads (
                    id TEXT PRIMARY KEY,
                    rollout_path TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                )
                """
            )
            conn.commit()
            conn.close()

            cmd = [
                sys.executable,
                "-m",
                "codex_rescue",
                "auto",
                "--repair-safe",
                "--no-prompt",
                "--json",
                "--codex-home",
                str(chome),
            ]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                env=env,
                timeout=5.0,
            )
            self.assertEqual(proc.returncode, 0, f"Stderr: {proc.stderr}")
            data = json.loads(proc.stdout)
            self.assertEqual(data["data"]["action_taken"], "REPAIRED")
            self.assertTrue(data["data"]["transaction"]["source_preserved"])


if __name__ == "__main__":
    unittest.main()

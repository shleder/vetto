from __future__ import annotations

import os
import platform
import select
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

SRC_DIR = str(Path(__file__).resolve().parent.parent.parent / "src")


class RealPtyInteractiveTests(unittest.TestCase):
    """Tests interactive surface selection under a REAL Pseudoterminal (PTY)."""

    def setUp(self):
        if platform.system() == "Windows":
            self.skipTest("Real PTY tests require POSIX pty support (Windows ConPTY marked NOT_QUALIFIED)")

    def _run_with_pty(self, inputs: list[str], codex_home: Path) -> str:
        """Spawns CLI process connected to a real openpty pair."""
        import pty
        import termios

        master_fd, slave_fd = pty.openpty()
        env = os.environ.copy()
        env["CODEX_HOME"] = str(codex_home)
        env["PYTHONPATH"] = f"{SRC_DIR}{os.pathsep}{env.get('PYTHONPATH', '')}"

        cmd = [sys.executable, "-m", "codex_rescue", "auto", "--codex-home", str(codex_home)]
        proc = subprocess.Popen(
            cmd,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            env=env,
            close_fds=True,
        )
        os.close(slave_fd)

        output = []
        input_idx = 0

        start_time = time.time()
        while time.time() - start_time < 5.0:
            r, _, _ = select.select([master_fd], [], [], 0.1)
            if master_fd in r:
                try:
                    data = os.read(master_fd, 1024)
                    if not data:
                        break
                    text = data.decode("utf-8", errors="replace")
                    output.append(text)

                    # When prompt appears and inputs remain, send next input
                    if "Select [1-4]:" in "".join(output) and input_idx < len(inputs):
                        inp = inputs[input_idx]
                        os.write(master_fd, inp.encode("utf-8"))
                        input_idx += 1
                except OSError:
                    break

            if proc.poll() is not None:
                # Read remaining output
                while True:
                    r, _, _ = select.select([master_fd], [], [], 0.05)
                    if master_fd in r:
                        try:
                            data = os.read(master_fd, 1024)
                            if not data:
                                break
                            output.append(data.decode("utf-8", errors="replace"))
                        except OSError:
                            break
                    else:
                        break
                break

        os.close(master_fd)
        proc.wait(timeout=2.0)
        return "".join(output)

    def _setup_multi_surface_env(self, chome: Path) -> None:
        # Create CLI rollout
        (chome / "sessions").mkdir(parents=True, exist_ok=True)
        (chome / "sessions" / "s1.jsonl").write_text('{"turn": 1}\n', encoding="utf-8")
        # Create Desktop state.db
        (chome / "state.db").write_text("", encoding="utf-8")

    def test_pty_interactive_select_1_cli(self):
        with tempfile.TemporaryDirectory() as td:
            chome = Path(td)
            self._setup_multi_surface_env(chome)
            out = self._run_with_pty(["1\n"], chome)
            self.assertIn("What do you want to inspect?", out)
            self.assertIn("CLI", out)

    def test_pty_interactive_select_2_desktop(self):
        with tempfile.TemporaryDirectory() as td:
            chome = Path(td)
            self._setup_multi_surface_env(chome)
            out = self._run_with_pty(["2\n"], chome)
            self.assertIn("DESKTOP", out)

    def test_pty_interactive_select_3_ide(self):
        with tempfile.TemporaryDirectory() as td:
            chome = Path(td)
            self._setup_multi_surface_env(chome)
            out = self._run_with_pty(["3\n"], chome)
            self.assertIn("IDE", out)

    def test_pty_interactive_select_4_all(self):
        with tempfile.TemporaryDirectory() as td:
            chome = Path(td)
            self._setup_multi_surface_env(chome)
            out = self._run_with_pty(["4\n"], chome)
            self.assertIn("ALL", out)

    def test_pty_interactive_invalid_reprompts(self):
        with tempfile.TemporaryDirectory() as td:
            chome = Path(td)
            self._setup_multi_surface_env(chome)
            # Send invalid "9\n", then valid "1\n"
            out = self._run_with_pty(["9\n", "1\n"], chome)
            self.assertIn("Invalid selection", out)
            self.assertIn("CLI", out)


if __name__ == "__main__":
    unittest.main()

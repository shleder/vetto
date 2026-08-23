from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from codex_rescue.gitstate import compare_git_state, inspect_git_state


class GitStateTests(unittest.TestCase):
    def test_hash_includes_staged_modified_and_untracked_content(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=root, check=True)
            (root / "tracked.txt").write_text("one\n", encoding="utf-8")
            subprocess.run(["git", "add", "tracked.txt"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "base"], cwd=root, check=True)

            before = inspect_git_state(root)
            (root / "tracked.txt").write_text("two\n", encoding="utf-8")
            (root / "new.bin").write_bytes(b"a\x00b")
            after = inspect_git_state(root)
            self.assertNotEqual(before.diff_hash, after.diff_hash)
            self.assertEqual(after.changed_files, ("new.bin", "tracked.txt"))

            conflicts = compare_git_state(before.to_dict(), after)
            self.assertTrue(any("diff_hash" in item for item in conflicts))


if __name__ == "__main__":
    unittest.main()


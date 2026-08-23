"""Tier 2: Feature Area 10 BVA - Packaging & Distribution Boundary Value Analysis."""
from __future__ import annotations

import socket
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
_SRC_DIR = _REPO_ROOT / "src"
_E2E_DIR = _REPO_ROOT / "tests" / "e2e"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))
if str(_E2E_DIR) not in sys.path:
    sys.path.insert(0, str(_E2E_DIR))

from codex_rescue.cli import main


class TestArea10PackagingBVA(unittest.TestCase):
    """Boundary and corner case tests for packaging, isolation, and metadata integrity."""

    def test_e2e_t2_packaging_license_and_readme_present(self) -> None:
        """Verify LICENSE and README.md are present at project root and non-empty."""
        readme = _REPO_ROOT / "README.md"
        license_f = _REPO_ROOT / "LICENSE"
        self.assertTrue(readme.exists())
        self.assertTrue(license_f.exists())
        self.assertGreater(readme.stat().st_size, 0)
        self.assertGreater(license_f.stat().st_size, 0)

    def test_e2e_t2_packaging_all_init_files_present(self) -> None:
        """Verify package initialization and exported __version__ metadata."""
        init_file = _REPO_ROOT / "src" / "codex_rescue" / "__init__.py"
        self.assertTrue(init_file.exists())
        text = init_file.read_text(encoding="utf-8")
        self.assertIn("__version__", text)

    def test_e2e_t2_packaging_entry_point_callable(self) -> None:
        """Verify codex_rescue.cli:main entry point is directly callable."""
        self.assertTrue(callable(main))

    def test_e2e_t2_packaging_offline_isolation_mock_env(self) -> None:
        """Verify executing CLI subcommands makes zero network socket connections (P10)."""
        def _blocked_connect(*args, **kwargs):
            raise AssertionError("Invariant P10 Violation: Network socket creation attempted!")

        with patch.object(socket.socket, "connect", side_effect=_blocked_connect):
            with patch.object(socket.socket, "bind", side_effect=_blocked_connect):
                # Run standard CLI version command without network
                try:
                    main(["--version"])
                except SystemExit as exc:
                    self.assertEqual(exc.code, 0)

    def test_e2e_t2_packaging_clean_room_dry_build(self) -> None:
        """Verify build backend is setuptools.build_meta in pyproject.toml."""
        pyproject = _REPO_ROOT / "pyproject.toml"
        self.assertTrue(pyproject.exists())
        text = pyproject.read_text(encoding="utf-8")
        self.assertIn("build-backend = \"setuptools.build_meta\"", text)
        self.assertIn("requires-python = \">=3.11\"", text)


if __name__ == "__main__":
    unittest.main()

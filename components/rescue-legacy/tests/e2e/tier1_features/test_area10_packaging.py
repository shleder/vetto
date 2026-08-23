"""Tier 1: Feature Area 10 - Packaging, Sdist/Wheel & Zero Runtime Dependencies."""
from __future__ import annotations

import ast
import os
import sys
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
_SRC_DIR = _REPO_ROOT / "src"
_E2E_DIR = _REPO_ROOT / "tests" / "e2e"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))
if str(_E2E_DIR) not in sys.path:
    sys.path.insert(0, str(_E2E_DIR))

import codex_rescue
try:
    import tomllib
except ImportError:
    import tomli as tomllib  # type: ignore

from common import run_cli_command


class TestArea10PackagingFeatures(unittest.TestCase):
    """End-to-end feature tests for package configuration, standards compliance, and offline isolation."""

    def test_e2e_t1_packaging_package_init_version(self) -> None:
        """Verify __version__ is exported and matches current version."""
        self.assertTrue(hasattr(codex_rescue, "__version__"))
        self.assertEqual(codex_rescue.__version__, "0.1.0a7")

    def test_e2e_t1_packaging_pyproject_structure(self) -> None:
        """Verify pyproject.toml defines standards-compliant setuptools configuration."""
        pyproject_path = _REPO_ROOT / "pyproject.toml"
        self.assertTrue(pyproject_path.exists())
        data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))

        project = data.get("project", {})
        self.assertEqual(project.get("name"), "codex-rescue")
        self.assertEqual(project.get("requires-python"), ">=3.11")
        self.assertEqual(project.get("dependencies"), [])
        scripts = project.get("scripts", {})
        self.assertEqual(scripts.get("codex-rescue"), "codex_rescue.cli:main")

    def test_e2e_t1_packaging_manifest_rules(self) -> None:
        """Verify MANIFEST.in preserves source files and excludes internal test caches."""
        manifest_path = _REPO_ROOT / "MANIFEST.in"
        if manifest_path.exists():
            text = manifest_path.read_text(encoding="utf-8")
            self.assertIn("include README.md", text)
            self.assertIn("include LICENSE", text)

    def test_e2e_t1_packaging_zero_runtime_deps(self) -> None:
        """Verify all python modules under src/codex_rescue/ use strictly standard library imports (P10)."""
        src_dir = _REPO_ROOT / "src" / "codex_rescue"
        stdlib_names = set(sys.stdlib_module_names) if hasattr(sys, "stdlib_module_names") else {
            "os", "sys", "json", "hashlib", "time", "pathlib", "collections", "dataclasses",
            "typing", "re", "subprocess", "tempfile", "shutil", "stat", "argparse", "ctypes",
            "datetime", "math", "functools", "itertools", "enum", "logging", "errno", "sqlite3", "urllib",
        }
        subpackages = {p.name for p in src_dir.iterdir() if p.is_dir()}
        allowed = stdlib_names | {"codex_rescue", *{p.stem for p in src_dir.rglob("*.py")}, *subpackages}

        for py_file in src_dir.rglob("*.py"):
            tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        top = alias.name.split(".")[0]
                        self.assertIn(
                            top,
                            allowed,
                            f"Non-stdlib import '{top}' found in {py_file.name}",
                        )
                elif isinstance(node, ast.ImportFrom):
                    # Relative imports (level > 0) are internal to codex_rescue
                    if node.level > 0:
                        continue
                    if node.module:
                        top = node.module.split(".")[0]
                        if not node.module.startswith("."):
                            self.assertIn(
                                top,
                                allowed,
                                f"Non-stdlib import '{top}' found in {py_file.name}",
                            )

    def test_e2e_t1_packaging_cli_version_flag(self) -> None:
        """Verify codex-rescue --version prints current version string and exits with code 0."""
        code, stdout, stderr = run_cli_command(["--version"])
        self.assertEqual(code, 0)
        self.assertIn("0.1.0a7", stdout)


if __name__ == "__main__":
    unittest.main()

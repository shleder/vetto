from __future__ import annotations

import json
import unittest
from pathlib import Path

from codex_rescue import __version__


ROOT = Path(__file__).resolve().parent.parent
CURRENT_NPM_META_VERSION = "0.1.0-alpha.7"
CURRENT_PLATFORM_VERSION = "0.1.0-alpha.7"
PYTHON_VERSION = "0.1.0a7"
TAG = "v0.1.0-alpha.7"

ALPHA5_NPM_VERSION = "0.1.0-alpha.5"
ALPHA5_PYTHON_VERSION = "0.1.0a5"
ALPHA5_TAG = "v0.1.0-alpha.5"
ALPHA4_TAG = "v0.1.0-alpha.4"
HISTORICAL_ALPHA6_WINDOWS_PACKAGE = "codex-rescue-win32-x64"
CURRENT_PLATFORM_PACKAGES = {
    "linux-x64": (
        "codex-rescue-linux-x64",
        "linux",
        "x64",
        "bin/codex-rescue",
        CURRENT_PLATFORM_VERSION,
    ),
    "win32-x64": (
        "codex-rescue-windows-x64",
        "win32",
        "x64",
        "bin/codex-rescue.exe",
        CURRENT_PLATFORM_VERSION,
    ),
    "darwin-arm64": (
        "codex-rescue-darwin-arm64",
        "darwin",
        "arm64",
        "bin/codex-rescue",
        CURRENT_PLATFORM_VERSION,
    ),
    "darwin-x64": (
        "codex-rescue-darwin-x64",
        "darwin",
        "x64",
        "bin/codex-rescue",
        CURRENT_PLATFORM_VERSION,
    ),
}


class Alpha5ReleaseConfigTests(unittest.TestCase):
    def test_current_alpha6_forward_publication_topology_is_exact(self) -> None:
        self.assertEqual(__version__, PYTHON_VERSION)
        meta = json.loads((ROOT / "npm/codex-rescue/package.json").read_text(encoding="utf-8"))
        self.assertEqual(meta["name"], "codex-rescue")
        self.assertEqual(meta["version"], CURRENT_NPM_META_VERSION)
        self.assertEqual(meta["files"], ["bin/codex-rescue.js", "README.md"])
        self.assertEqual(
            meta["optionalDependencies"],
            {name: dependency for name, _, _, _, dependency in CURRENT_PLATFORM_PACKAGES.values()},
        )
        self.assertNotIn(HISTORICAL_ALPHA6_WINDOWS_PACKAGE, meta["optionalDependencies"])

        seen: set[str] = set()
        for platform_id, (name, os_name, cpu, binary, _) in CURRENT_PLATFORM_PACKAGES.items():
            package = json.loads(
                (ROOT / f"npm/platforms/{platform_id}/package.json").read_text(encoding="utf-8")
            )
            seen.add(package["name"])
            self.assertEqual(package["name"], name)
            self.assertEqual(package["version"], CURRENT_PLATFORM_VERSION)
            self.assertEqual(package["os"], [os_name])
            self.assertEqual(package["cpu"], [cpu])
            self.assertEqual(package["files"], [binary, "README.md"])
            self.assertNotIn("scripts", package)
        self.assertEqual(seen, {value[0] for value in CURRENT_PLATFORM_PACKAGES.values()})

    def test_alpha6_windows_launcher_keeps_history_only_as_fallback(self) -> None:
        launcher = (ROOT / "npm/codex-rescue/bin/codex-rescue.js").read_text(encoding="utf-8")
        current = "'codex-rescue-windows-x64'"
        historical = "'codex-rescue-win32-x64'"
        self.assertIn(current, launcher)
        self.assertIn(historical, launcher)
        self.assertLess(launcher.index(current), launcher.index(historical))

    def test_alpha5_release_candidate_history_remains_manual_exact_and_immutable(self) -> None:
        text = (ROOT / ".github/workflows/alpha5-release-candidate.yml").read_text(encoding="utf-8")
        trigger = text.split("permissions:", 1)[0]
        default_permissions = text.split("permissions:", 1)[1].split("env:", 1)[0]
        self.assertIn("workflow_dispatch:", trigger)
        self.assertNotIn("\n  push:", trigger)
        self.assertNotIn("\n  pull_request:", trigger)
        self.assertIn("contents: read", default_permissions)
        self.assertIn("actions: read", default_permissions)
        self.assertNotIn("id-token: write", default_permissions)
        self.assertIn(f"EXPECTED_TAG: {ALPHA5_TAG}", text)
        self.assertIn(f"EXPECTED_PYTHON_VERSION: {ALPHA5_PYTHON_VERSION}", text)
        self.assertIn(f"EXPECTED_NPM_VERSION: {ALPHA5_NPM_VERSION}", text)
        self.assertIn("PYINSTALLER_VERSION: 6.22.1", text)
        self.assertIn("BUILD_VERSION: 1.5.0", text)
        self.assertIn("TWINE_VERSION: 7.0.0", text)
        self.assertIn("SETUPTOOLS_VERSION: 84.0.0", text)
        self.assertIn("platform_package: codex-rescue-win32-x64", text)
        self.assertNotIn("platform_package: codex-rescue-windows-x64", text)
        expected_files = {
            "codex_rescue-0.1.0a5-py3-none-any.whl",
            "codex_rescue-0.1.0a5.tar.gz",
            "codex-rescue-0.1.0-alpha.5.tgz",
            "codex-rescue-linux-x64-0.1.0-alpha.5.tgz",
            "codex-rescue-win32-x64-0.1.0-alpha.5.tgz",
            "codex-rescue-darwin-arm64-0.1.0-alpha.5.tgz",
            "codex-rescue-darwin-x64-0.1.0-alpha.5.tgz",
            "codex-rescue-linux-x64",
            "codex-rescue-win32-x64.exe",
            "codex-rescue-darwin-arm64",
            "codex-rescue-darwin-x64",
        }
        for filename in expected_files:
            self.assertIn(filename, text)
        self.assertIn("candidate file set mismatch", text)
        self.assertIn("release-manifest.json", text)
        self.assertIn("SHA256SUMS", text)

    def test_alpha5_publish_policy_history_is_preserved(self) -> None:
        handoff = (ROOT / "docs/alpha5-release-handoff.md").read_text(encoding="utf-8")
        self.assertIn("PYPI_ALPHA5_POLICY: OFFICIAL_RELEASE_CHANNEL", handoff)
        self.assertIn("GitHub Release / standalone native binaries", handoff)
        self.assertIn("npx codex-rescue@0.1.0-alpha.5", handoff)
        self.assertIn("pip install codex-rescue==0.1.0a5", handoff)
        self.assertIn("pipx install codex-rescue==0.1.0a5", handoff)

    def test_alpha4_history_remains_locked_in_changelog(self) -> None:
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn(f"## {ALPHA4_TAG}", changelog)
        alpha4 = changelog.split(f"## {ALPHA4_TAG}", 1)[1].split("## v0.1.0-alpha.3", 1)[0]
        self.assertIn("Detect persisted rollout-local reuse of paginated ordinals.", alpha4)
        self.assertIn("Source rollouts", changelog)
        self.assertIn("read-only", changelog)


if __name__ == "__main__":
    unittest.main()

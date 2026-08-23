from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from codex_rescue.alpha7.compatibility.engine import CompatibilityEngine
from codex_rescue.alpha7.compatibility.path_remap import PathRemappingEngine
from codex_rescue.alpha7.compatibility.portable import PortableSessionEngine
from codex_rescue.alpha7.graph import PathNamespace


class CompatibilityAndPortableTests(unittest.TestCase):
    def test_compatibility_engine(self):
        # Supported schemas
        c1 = CompatibilityEngine.evaluate(rollout_schema=1, sqlite_schema=1)
        self.assertTrue(c1.mutation_schema_compatible)
        self.assertFalse(c1.mutation_allowed)  # Mutation gate fails closed; HOLD
        self.assertEqual(c1.verdict, "SUPPORTED")

        # Unknown rollout schema
        c2 = CompatibilityEngine.evaluate(rollout_schema=99, sqlite_schema=1)
        self.assertFalse(c2.mutation_allowed)
        self.assertFalse(c2.mutation_schema_compatible)
        self.assertEqual(c2.rejection_reason, "UNKNOWN_ROLLOUT_SCHEMA_99")

        # Unknown sqlite schema
        c3 = CompatibilityEngine.evaluate(rollout_schema=1, sqlite_schema=99)
        self.assertFalse(c3.mutation_allowed)
        self.assertFalse(c3.mutation_schema_compatible)
        self.assertEqual(c3.rejection_reason, "UNKNOWN_SQLITE_SCHEMA_99")

    def test_path_remapping_engine(self):
        # Windows to WSL
        r1 = PathRemappingEngine.translate_path(r"C:\Users\Project\src", target_platform="wsl")
        self.assertEqual(r1.target_path, "/mnt/c/Users/Project/src")
        self.assertEqual(r1.target_namespace, PathNamespace.WSL_MNT)

        # WSL to Windows
        r2 = PathRemappingEngine.translate_path("/mnt/d/code/rescue", target_platform="windows")
        self.assertEqual(r2.target_path, r"D:\code\rescue")
        self.assertEqual(r2.target_namespace, PathNamespace.WINDOWS_STANDARD)

        # Long path prefix stripping
        r3 = PathRemappingEngine.translate_path(r"\\?\C:\foo\bar", target_platform="windows")
        self.assertEqual(r3.target_path, r"C:\foo\bar")

    def test_portable_export_inspect_import_lifecycle(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            session_uuid = "11111111-2222-3333-4444-555555555555"
            fname = f"rollout-2026-08-19T12-00-00-{session_uuid}.jsonl"
            source_file = tmp / fname
            source_file.write_text('{"turn":1,"msg":"hello"}\n{"turn":2,"msg":"world"}\n', encoding="utf-8")

            pkg_zip = tmp / "export.rescue.zip"
            manifest = PortableSessionEngine.export_session(
                source_file, pkg_zip, workspace_path=r"C:\workspaces\project"
            )
            self.assertEqual(manifest.session_id, session_uuid)
            self.assertEqual(manifest.thread_id, session_uuid)
            self.assertEqual(manifest.identity_status, "RESOLVED")
            self.assertEqual(manifest.records_count, 2)
            self.assertEqual(manifest.source_integrity, "HEALTHY")
            self.assertEqual(manifest.package_classification, "SAFE_MIGRATION_PACKAGE")

            # Inspect
            inspected = PortableSessionEngine.inspect_package(pkg_zip)
            self.assertEqual(inspected.session_id, session_uuid)
            self.assertEqual(inspected.rollout_sha256, manifest.rollout_sha256)

            # Plan import into target codex home
            target_home = tmp / "target_codex"
            plan = PortableSessionEngine.plan_import(pkg_zip, target_home)
            self.assertTrue(plan.is_safe)
            self.assertFalse(plan.has_conflict)

            # Dry run
            dry_res = PortableSessionEngine.execute_import(pkg_zip, target_home, plan, dry_run=True)
            self.assertTrue(dry_res["success"])
            self.assertEqual(dry_res["action"], "DRY_RUN_PASSED")

            # Staging only import (Rescue-owned staging)
            stage_res = PortableSessionEngine.execute_import(pkg_zip, target_home, plan, dry_run=False, stage_only=True)
            self.assertTrue(stage_res["success"])
            self.assertEqual(stage_res["stage"], "STAGED")
            self.assertFalse(stage_res["index_visible"])

            # Live Codex import fails closed because no supported registration path exists in live Codex
            live_res = PortableSessionEngine.execute_import(pkg_zip, target_home, plan, dry_run=False, stage_only=False)
            self.assertFalse(live_res["success"])
            self.assertEqual(live_res["action"], "IMPORT_BLOCKED")
            self.assertEqual(live_res["reason"], "NO_SUPPORTED_CODEX_REGISTRATION_PATH")
            self.assertFalse(live_res["index_visible"])


if __name__ == "__main__":
    unittest.main()

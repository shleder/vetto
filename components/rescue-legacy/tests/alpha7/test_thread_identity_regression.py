from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from codex_rescue.alpha7.compatibility.portable import PortableSessionEngine
from codex_rescue.alpha7.surfaces.desktop import DesktopAdapter
from codex_rescue.alpha7.surfaces.router import DiagnosticRouter
from codex_rescue.thread_identity import parse_rollout_filename, resolve_thread_identity


class ThreadIdentityRegressionTests(unittest.TestCase):
    def test_canonical_upstream_normal_rollout_filename(self) -> None:
        fname = "rollout-2026-08-19T12-00-00-11111111-2222-3333-4444-555555555555.jsonl"
        ident = parse_rollout_filename(fname)
        self.assertIsNotNone(ident)
        self.assertEqual(ident.thread_id, "11111111-2222-3333-4444-555555555555")
        self.assertEqual(ident.rollout_id, "11111111-2222-3333-4444-555555555555")

        res = resolve_thread_identity(fname)
        self.assertEqual(res.thread_id, "11111111-2222-3333-4444-555555555555")
        self.assertEqual(res.filename_rollout_id, "11111111-2222-3333-4444-555555555555")

    def test_canonical_upstream_revert_rollout_filename_distinguishes_thread_and_rollout(self) -> None:
        fname = "rollout-2026-08-19T12-00-00-11111111-2222-3333-4444-555555555555_66666666-7777-8888-9999-000000000000.jsonl"
        ident = parse_rollout_filename(fname)
        self.assertIsNotNone(ident)
        self.assertEqual(ident.thread_id, "11111111-2222-3333-4444-555555555555")
        self.assertEqual(ident.rollout_id, "66666666-7777-8888-9999-000000000000")

        res = resolve_thread_identity(fname)
        self.assertEqual(res.thread_id, "11111111-2222-3333-4444-555555555555")
        self.assertEqual(res.filename_rollout_id, "66666666-7777-8888-9999-000000000000")

    def test_unresolved_non_canonical_filename_has_no_stem_fallback(self) -> None:
        for non_canonical in ["cli_test.jsonl", "arbitrary_session.jsonl", "rollout-invalid-date.jsonl"]:
            res = resolve_thread_identity(non_canonical)
            self.assertIsNone(res.thread_id, f"Failed for {non_canonical}: must not use stem fallback")
            self.assertIsNone(res.filename_thread_id)
            self.assertEqual(res.source, "UNKNOWN")

    def test_portable_export_of_unresolved_identity_blocks_safe_migration(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            session_file = Path(td) / "unresolved_legacy.jsonl"
            session_file.write_text('{"turn":1}\n', encoding="utf-8")
            zip_target = Path(td) / "export.zip"

            manifest = PortableSessionEngine.export_session(session_file, zip_target)
            self.assertIsNone(manifest.thread_id)
            self.assertEqual(manifest.identity_status, "UNRESOLVED")
            self.assertEqual(manifest.package_classification, "FORENSIC_PACKAGE")
            self.assertNotEqual(manifest.package_classification, "SAFE_MIGRATION_PACKAGE")

    def test_router_handles_unresolved_identity_as_identity_unknown_not_not_found(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            sessions_dir = home / "sessions"
            sessions_dir.mkdir(parents=True)
            non_canonical = sessions_dir / "unresolved_test.jsonl"
            non_canonical.write_text('{"turn":1}\n', encoding="utf-8")

            router = DiagnosticRouter(codex_home=home)
            route = router.route_session(non_canonical)
            self.assertIn("IDENTITY_UNKNOWN", route.findings)
            self.assertNotIn("THREAD_NOT_FOUND", route.findings)
            self.assertEqual(route.confidence, "UNKNOWN")
            self.assertIn("MUTATION_BLOCKED_UNRESOLVED_IDENTITY", route.blocked_actions)


if __name__ == "__main__":
    unittest.main()

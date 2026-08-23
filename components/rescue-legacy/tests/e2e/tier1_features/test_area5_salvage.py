"""Tier 1: Feature Area 5 - Forked Salvage & Source Immutability (P1, P2)."""
from __future__ import annotations

import hashlib
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

from codex_rescue.doctor import doctor_session
from codex_rescue.salvage import salvage_session
from codex_rescue.transcript import parse_transcript
from common import SyntheticRolloutGenerator, TempSessionWorkspace


class TestArea5SalvageFeatures(unittest.TestCase):
    """End-to-end feature tests for forked salvage and non-negotiable source immutability."""

    def test_e2e_t1_salvage_fork_flag_enforced(self) -> None:
        """Verify salvage strictly refuses execution unless fork=True is explicitly supplied (P2)."""
        with TempSessionWorkspace() as ws:
            p = ws.create_session("fork-flag-001")
            parsed = parse_transcript(str(p))
            doc = doctor_session(p)

            with self.assertRaises(ValueError) as ctx:
                salvage_session(
                    session_path=p,
                    parsed=parsed,
                    doctor_status=doc.status,
                    findings=doc.findings,
                    rescue_root=ws.root / "rescues",
                    fork=False,
                )
            self.assertIn("fork", str(ctx.exception).lower())

    def test_e2e_t1_salvage_source_byte_immutability(self) -> None:
        """Verify source session bytes and SHA-256 digest are 100% untouched before/after salvage (P1)."""
        with TempSessionWorkspace() as ws:
            p = ws.create_session("immutable-001")
            bytes_before = p.read_bytes()
            sha_before = hashlib.sha256(bytes_before).hexdigest()

            parsed = parse_transcript(str(p))
            doc = doctor_session(p)
            rescue_root = ws.root / "rescues"

            res = salvage_session(
                session_path=p,
                parsed=parsed,
                doctor_status=doc.status,
                findings=doc.findings,
                rescue_root=rescue_root,
                fork=True,
            )

            bytes_after = p.read_bytes()
            sha_after = hashlib.sha256(bytes_after).hexdigest()

            self.assertEqual(bytes_before, bytes_after)
            self.assertEqual(sha_before, sha_after)
            self.assertTrue(res.original_untouched)
            self.assertEqual(res.source_sha256_before, sha_before)
            self.assertEqual(res.source_sha256_after, sha_after)

    def test_e2e_t1_salvage_artifact_structure(self) -> None:
        """Verify complete set of recovery artifacts are written to isolated target directory."""
        with TempSessionWorkspace() as ws:
            p = ws.create_session("artifacts-001")
            parsed = parse_transcript(str(p))
            doc = doctor_session(p)
            rescue_root = ws.root / "rescues"

            res = salvage_session(
                session_path=p,
                parsed=parsed,
                doctor_status=doc.status,
                findings=doc.findings,
                rescue_root=rescue_root,
                fork=True,
            )

            rescue_dir = Path(res.rescue_dir)
            self.assertTrue(rescue_dir.exists())
            self.assertTrue((rescue_dir / "handoff.v1.json").exists())
            self.assertTrue((rescue_dir / "RECOVERY_BRIEF.md").exists())
            self.assertTrue((rescue_dir / "CONTINUATION_PROMPT.md").exists())

    def test_e2e_t1_salvage_content_addressed_id(self) -> None:
        """Verify content-addressed 24-character rescue ID is deterministic across separate roots."""
        with TempSessionWorkspace() as ws:
            p = ws.create_session("content-addr-001")
            parsed = parse_transcript(str(p))
            doc = doctor_session(p)

            root1 = ws.root / "rescues_run1"
            root2 = ws.root / "rescues_run2"

            res1 = salvage_session(p, parsed, doc.status, doc.findings, root1, fork=True)
            res2 = salvage_session(p, parsed, doc.status, doc.findings, root2, fork=True)

            self.assertEqual(len(res1.rescue_id), 24)
            self.assertEqual(res1.rescue_id, res2.rescue_id)

    def test_e2e_t1_salvage_continuation_command(self) -> None:
        """Verify generated continuation command and argv reference handoff JSON cleanly."""
        with TempSessionWorkspace() as ws:
            p = ws.create_session("continuation-001")
            parsed = parse_transcript(str(p))
            doc = doctor_session(p)
            rescue_root = ws.root / "rescues"

            res = salvage_session(p, parsed, doc.status, doc.findings, rescue_root, fork=True)

            self.assertIn("handoff.v1.json", res.continuation_command)
            self.assertTrue(any("handoff.v1.json" in arg for arg in res.continuation_argv))
            self.assertEqual(len(res.continuation_argv), 4)


if __name__ == "__main__":
    unittest.main()

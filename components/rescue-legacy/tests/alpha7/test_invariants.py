from __future__ import annotations

import unittest
from codex_rescue.alpha7.invariants import InvariantCheckResult, InvariantEngine, InvariantId, InvariantStatus


class Alpha7InvariantTests(unittest.TestCase):
    def test_inv_001_source_accounting_complete(self):
        res = InvariantEngine.check_source_accounting(total_bytes=1000, scanned_bytes=1000, unclassified_bytes=0)
        self.assertTrue(res.passed)
        self.assertEqual(res.status, InvariantStatus.PASS)

    def test_inv_001_unclassified_bytes_fails(self):
        res = InvariantEngine.check_source_accounting(total_bytes=1000, scanned_bytes=1000, unclassified_bytes=50)
        self.assertFalse(res.passed)
        self.assertEqual(res.status, InvariantStatus.FAIL)
        self.assertEqual(res.invariant_id, InvariantId.INV_001)

    def test_inv_014_partial_scan_fails(self):
        res = InvariantEngine.check_source_accounting(total_bytes=1000, scanned_bytes=800)
        self.assertFalse(res.passed)
        self.assertEqual(res.status, InvariantStatus.FAIL)
        self.assertEqual(res.invariant_id, InvariantId.INV_014)

    def test_inv_002_source_immutability_preserved(self):
        res = InvariantEngine.check_source_immutability(
            initial_hash="abc123sha", current_hash="abc123sha", is_derived_recovery=True
        )
        self.assertTrue(res.passed)

    def test_inv_002_source_mutation_during_derived_recovery_fails(self):
        res = InvariantEngine.check_source_immutability(
            initial_hash="abc123sha", current_hash="corrupted456", is_derived_recovery=True
        )
        self.assertFalse(res.passed)
        self.assertEqual(res.status, InvariantStatus.FAIL)
        self.assertEqual(res.invariant_id, InvariantId.INV_002)

    def test_inv_003_active_writer_blocks_mutation(self):
        res = InvariantEngine.check_active_writer(
            has_active_writer=True, writer_pid=12345, is_mutation_operation=True
        )
        self.assertFalse(res.passed)
        self.assertEqual(res.status, InvariantStatus.FAIL)
        self.assertEqual(res.invariant_id, InvariantId.INV_003)

    def test_inv_003_active_writer_read_only_allowed(self):
        res = InvariantEngine.check_active_writer(
            has_active_writer=True, writer_pid=12345, is_mutation_operation=False
        )
        self.assertTrue(res.passed)

    def test_inv_007_supported_schema_passes(self):
        res = InvariantEngine.check_schema_support(
            schema_version=1, supported_versions={1, 2}, is_mutation_operation=True
        )
        self.assertTrue(res.passed)

    def test_inv_007_unknown_schema_blocks_mutation(self):
        res = InvariantEngine.check_schema_support(
            schema_version=99, supported_versions={1, 2}, is_mutation_operation=True
        )
        self.assertFalse(res.passed)
        self.assertEqual(res.status, InvariantStatus.FAIL)
        self.assertEqual(res.invariant_id, InvariantId.INV_007)

    def test_inv_009_inv_010_yes_and_no_prompt_cannot_bypass_safety(self):
        res_yes = InvariantEngine.check_flags_cannot_bypass_safety(
            yes_flag=True, no_prompt_flag=False, blocked_reason="Active writer lock"
        )
        self.assertFalse(res_yes.passed)
        self.assertEqual(res_yes.invariant_id, InvariantId.INV_009)

        res_np = InvariantEngine.check_flags_cannot_bypass_safety(
            yes_flag=False, no_prompt_flag=True, blocked_reason="Corrupt source"
        )
        self.assertFalse(res_np.passed)
        self.assertEqual(res_np.invariant_id, InvariantId.INV_010)


if __name__ == "__main__":
    unittest.main()

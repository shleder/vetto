from __future__ import annotations

import contextlib
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path

from codex_rescue.alpha7.autopilot import AutopilotEngine
from codex_rescue.alpha7.privacy.redaction import PrivacyRedactionEngine
from codex_rescue.alpha7.selftest import SelfTestEngine
from codex_rescue.alpha7.simulation.simulator import RepairSimulator
from codex_rescue.cli import main


@contextlib.contextmanager
def safe_temp_codex_home():
    td = tempfile.mkdtemp()
    try:
        yield Path(td)
    finally:
        if os.name == "nt":
            time.sleep(0.2)
        shutil.rmtree(td, ignore_errors=True)


class AutopilotAndCLITests(unittest.TestCase):
    def test_autopilot_engine_run(self):
        with safe_temp_codex_home() as chome:
            engine = AutopilotEngine(chome)
            res = engine.run_autopilot(surface="all")
            self.assertEqual(res.selected_surface, "all")
            self.assertEqual(res.action_taken, "INSPECTED")

    def test_repair_simulator(self):
        with safe_temp_codex_home() as tmp:
            rollout = tmp / "session_sim.jsonl"
            rollout.write_text('{"turn":1}\n', encoding="utf-8")

            sim_res = RepairSimulator.simulate_derived_index_repair(rollout)
            self.assertEqual(sim_res.status, "PASS")
            self.assertTrue(sim_res.source_preserved)
            self.assertTrue(sim_res.safe_to_apply)

    def test_privacy_redaction_and_safe_share(self):
        text_with_secret = "Here is my token: sk-abcdef1234567890abcdef123456 and path C:\\Users\\Administrator\\project"
        sanitized, audit = PrivacyRedactionEngine.sanitize_text(text_with_secret)
        self.assertNotIn("sk-abcdef", sanitized)
        self.assertIn("[REDACTED_SECRET]", sanitized)
        self.assertTrue(audit.passed_validation)

        share_report = PrivacyRedactionEngine.create_safe_share_report("Windows", "Desktop", "HEALTHY", [])
        self.assertIn("Codex Rescue Alpha7 Lab", share_report)
        self.assertIn("Privacy validation: PASS", share_report)

    def test_self_test_engine(self):
        with safe_temp_codex_home() as td:
            rep = SelfTestEngine.run_self_test(td)
            self.assertEqual(rep.rescue_runtime_status, "PASS")
            self.assertEqual(rep.backup_engine_status, "PASS")
            self.assertEqual(rep.invariant_engine_status, "PASS")
            self.assertIn(rep.overall_status, ("PASS", "LIMITED"))

    def test_cli_dispatches(self):
        with safe_temp_codex_home() as chome:
            # 1. auto
            code_auto = main(["auto", "--codex-home", str(chome), "--json"])
            self.assertEqual(code_auto, 0)

            # 2. self-test
            code_st = main(["self-test", "--codex-home", str(chome), "--json"])
            self.assertEqual(code_st, 0)

            # 3. compatibility
            code_comp = main(["compatibility", "--rollout-schema", "1", "--json"])
            self.assertEqual(code_comp, 0)

            # 4. desktop
            code_desk = main(["desktop", "status", "--codex-home", str(chome), "--json"])
            self.assertIn(code_desk, (0, 2))


if __name__ == "__main__":
    unittest.main()

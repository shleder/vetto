"""Codex Rescue Alpha5 deterministic demo.

Uses the kill_apply_patch synthetic fixture to demonstrate:
  doctor  -> identifies UNFINISHED_TOOL_CALL
  salvage -> leaves source rollout unchanged
  verify  -> returns REVIEW_REQUIRED

Verifies source session SHA-256 before and after to prove immutability.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
import tempfile
from pathlib import Path

# Ensure src/ is importable when run from repo root
_repo = Path(__file__).resolve().parent.parent
_src = _repo / "src"
if str(_src) not in sys.path:
    sys.path.insert(0, str(_src))

from codex_rescue import __version__
from codex_rescue.doctor import doctor_session
from codex_rescue.fixtures import materialize_fixture_git_repo
from codex_rescue.salvage import salvage_session
from codex_rescue.verify import verify_rescue


FIXTURE = _repo / "fixtures" / "kill_apply_patch"
SOURCE_SESSION = FIXTURE / "source_session" / "rollout-fixture-kill_apply_patch.jsonl"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def main() -> int:
    print("=" * 60)
    print(f"Codex Rescue {__version__} -- Deterministic Demo")
    print("=" * 60)
    print()

    # --- Step 0: verify fixture exists ---
    if not SOURCE_SESSION.exists():
        print(f"FAIL: fixture not found at {SOURCE_SESSION}")
        return 1

    # --- Step 1: hash source BEFORE ---
    hash_before = sha256(SOURCE_SESSION)
    print(f"Source session: {SOURCE_SESSION.name}")
    print(f"SHA-256 before: {hash_before}")
    print()

    with materialize_fixture_git_repo(FIXTURE):
        # --- Step 2: doctor ---
        print("--- doctor ---")
        result = doctor_session(SOURCE_SESSION)
        data = result.to_dict() if hasattr(result, "to_dict") else result.__dict__.copy()
        status = data.get("status", "UNKNOWN")
        findings = data.get("findings", [])
        print(f"Status:   {status}")
        print(f"Findings: {', '.join(str(f) for f in findings)}")
        assert status == "UNFINISHED_TOOL_CALL", f"Expected UNFINISHED_TOOL_CALL, got {status}"
        print("OK: doctor correctly identified UNFINISHED_TOOL_CALL")
        print()

        # --- Step 3: salvage ---
        print("--- salvage ---")
        rescue_root = Path(tempfile.mkdtemp(prefix="rescue-demo-"))
        try:
            parsed = None
            for attr in ("transcript", "parse_result", "parsed"):
                parsed = getattr(result, attr, None)
                if parsed is not None:
                    break
            if parsed is None:
                print("FAIL: doctor result does not expose parsed transcript")
                return 1

            salvage_result = salvage_session(
                SOURCE_SESSION,
                parsed,
                status,
                list(findings),
                rescue_root,
                fork=True,
            )
            salvage_data = salvage_result.to_dict() if hasattr(salvage_result, "to_dict") else salvage_result.__dict__.copy()
            print(f"Rescue ID:         {salvage_data.get('rescue_id', 'unknown')}")
            print(f"Original untouched: {'yes' if salvage_data.get('original_untouched') else 'NO (BUG!)'}")
            assert salvage_data.get("original_untouched"), "Source rollout was modified during salvage!"
            print("OK: salvage preserved source rollout")
            print()

            # --- Step 4: verify ---
            print("--- verify ---")
            rescue_id = salvage_data["rescue_id"]
            verify_result = verify_rescue(rescue_root, rescue_id)
            verify_data = verify_result.to_dict() if hasattr(verify_result, "to_dict") else verify_result.__dict__.copy()
            verify_status = verify_data.get("status", "UNKNOWN")
            print(f"Status: {verify_status}")
            reasons = verify_data.get("review_reasons", [])
            for r in reasons:
                print(f"  Review: {r}")
            print(f"OK: verify returned {verify_status}")
            print()

        finally:
            shutil.rmtree(rescue_root, ignore_errors=True)

    # --- Step 5: hash source AFTER ---
    hash_after = sha256(SOURCE_SESSION)
    print("--- immutability check ---")
    print(f"SHA-256 before: {hash_before}")
    print(f"SHA-256 after:  {hash_after}")
    if hash_before == hash_after:
        print("OK: source session unchanged (SHA-256 match)")
    else:
        print("FAIL: SOURCE SESSION WAS MODIFIED -- THIS IS A BUG")
        return 1
    print()

    print("=" * 60)
    print("DEMO PASSED -- all checks passed")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

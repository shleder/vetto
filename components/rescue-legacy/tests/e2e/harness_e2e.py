"""E2E Test Runner and Dual CLI/Unittest Harness.

Validates:
- Cryptographic SHA-256 tree hash of src/ and fixtures/ before and after test execution.
- Multi-tier filtering (--tier 1,2,3,4,all) and feature area filtering (--area 1..10).
- Detailed JSON telemetry reports (--json-report <path>).
- Clean exit codes (0 = all passed + immutable; non-zero = failures/invariant violations).
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import unittest
from pathlib import Path
from typing import Any

# Ensure src/ is in sys.path
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_SRC_DIR = _REPO_ROOT / "src"
_FIXTURES_DIR = _REPO_ROOT / "fixtures"
_E2E_DIR = _REPO_ROOT / "tests" / "e2e"

if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))
if str(_E2E_DIR) not in sys.path:
    sys.path.insert(0, str(_E2E_DIR))

from codex_rescue import __version__  # noqa: E402
from common import compute_tree_sha256  # noqa: E402


def build_suite(tier: str = "all", area: int | None = None) -> unittest.TestSuite:
    """Construct test suite based on tier and area filters."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    tier_dirs = {
        "1": _E2E_DIR / "tier1_features",
        "2": _E2E_DIR / "tier2_boundaries",
        "3": _E2E_DIR / "tier3_interactions",
        "4": _E2E_DIR / "tier4_scenarios",
    }

    selected_dirs: list[Path] = []
    if tier == "all":
        selected_dirs = list(tier_dirs.values())
    elif tier in tier_dirs:
        selected_dirs = [tier_dirs[tier]]
    else:
        raise ValueError(f"Unknown tier: {tier}")

    for t_dir in selected_dirs:
        if not t_dir.exists():
            continue
        if area is not None and t_dir.name in ("tier1_features", "tier2_boundaries"):
            pattern = f"test_area{area}_*.py"
            discovered = loader.discover(str(t_dir), pattern=pattern, top_level_dir=str(_REPO_ROOT))
            suite.addTests(discovered)
        else:
            discovered = loader.discover(str(t_dir), pattern="test_*.py", top_level_dir=str(_REPO_ROOT))
            suite.addTests(discovered)

    return suite


def load_tests(loader: unittest.TestLoader, tests: unittest.TestSuite, pattern: str | None) -> unittest.TestSuite:
    """Standard unittest hook for discover-based execution."""
    return build_suite("all")


def run_e2e(
    tier: str = "all",
    area: int | None = None,
    verbose: bool = False,
    json_report_path: str | None = None,
) -> int:
    """Run E2E suite with pre/post immutability verification and telemetry."""
    print(f"=== Codex Rescue ({__version__}) E2E Test Runner ===")
    print(f"Target: Tier={tier}, Area={area or 'all'}, Verbosity={'verbose' if verbose else 'normal'}")

    # 1. Pre-execution SHA-256 tree hashing
    src_sha_before = compute_tree_sha256(_SRC_DIR)
    fixtures_sha_before = compute_tree_sha256(_FIXTURES_DIR)
    print(f"[Pre-Flight] src/ SHA-256:      {src_sha_before[:16]}...")
    print(f"[Pre-Flight] fixtures/ SHA-256: {fixtures_sha_before[:16]}...")

    start_time = time.perf_counter()
    suite = build_suite(tier=tier, area=area)
    total_tests = suite.countTestCases()
    print(f"[Suite Built] Loaded {total_tests} test cases.")

    runner = unittest.TextTestRunner(verbosity=2 if verbose else 1)
    result = runner.run(suite)
    elapsed = time.perf_counter() - start_time

    # 2. Post-execution SHA-256 tree hashing (Invariant P1 check)
    src_sha_after = compute_tree_sha256(_SRC_DIR)
    fixtures_sha_after = compute_tree_sha256(_FIXTURES_DIR)
    print(f"[Post-Flight] src/ SHA-256:     {src_sha_after[:16]}...")
    print(f"[Post-Flight] fixtures/ SHA-256:{fixtures_sha_after[:16]}...")

    immutability_ok = (src_sha_before == src_sha_after) and (fixtures_sha_before == fixtures_sha_after)
    if not immutability_ok:
        print("\nFATAL INVARIANT P1 VIOLATION: Source or fixture tree was modified during test run!")
        if src_sha_before != src_sha_after:
            print(f"  src/ digest mismatch: before={src_sha_before} after={src_sha_after}")
        if fixtures_sha_before != fixtures_sha_after:
            print(f"  fixtures/ digest mismatch: before={fixtures_sha_before} after={fixtures_sha_after}")

    passed = total_tests - len(result.failures) - len(result.errors) - len(result.skipped)

    telemetry: dict[str, Any] = {
        "version": __version__,
        "tier": tier,
        "area": area,
        "total_tests": total_tests,
        "passed": passed,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "elapsed_seconds": round(elapsed, 3),
        "source_immutable": immutability_ok,
        "all_passed": result.wasSuccessful() and immutability_ok,
    }

    if json_report_path:
        out_p = Path(json_report_path).resolve()
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(json.dumps(telemetry, indent=2), encoding="utf-8")
        print(f"[Report] JSON telemetry written to: {out_p}")

    print("\n=== E2E Summary ===")
    print(f"Tests: {passed}/{total_tests} passed, {len(result.failures)} failed, {len(result.errors)} errors, {len(result.skipped)} skipped in {elapsed:.2f}s")
    print(f"Invariant P1 (Source Immutability): {'PASSED' if immutability_ok else 'FAILED'}")

    if not result.wasSuccessful() or not immutability_ok:
        return 1 if result.wasSuccessful() else 2
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Codex Rescue E2E Test Harness")
    parser.add_argument("--tier", choices=["all", "1", "2", "3", "4"], default="all", help="Test tier to execute")
    parser.add_argument("--area", type=int, choices=range(1, 11), default=None, help="Feature area (1..10)")
    parser.add_argument("--json-report", type=str, default=None, help="Path to write JSON test report")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose test runner output")

    args = parser.parse_args()
    exit_code = run_e2e(
        tier=args.tier,
        area=args.area,
        verbose=args.verbose,
        json_report_path=args.json_report,
    )
    sys.exit(exit_code)


if __name__ == "__main__":
    main()

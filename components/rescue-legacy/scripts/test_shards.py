"""Run the disjoint local unittest shards.

This helper is intentionally separate from the CI full-suite command.  It
uses only the standard library and never changes which tests the full gate
collects.  Add a new ``tests/test_*.py`` file to exactly one shard before
using this manifest for parallel feedback.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import Final


ROOT: Final = Path(__file__).resolve().parents[1]

# Keep these sets disjoint.  The two empty entries are reserved for checks
# that are not currently represented by a test module in this repository.
SHARDS: Final[dict[str, tuple[str, ...]]] = {
    "FAST_CORE": (
        "tests.test_journal",
        "tests.test_previous_format",
        "tests.test_reconstruct",
        "tests.test_transcript",
    ),
    "DOCTOR_TRANSCRIPT": (
        "tests.test_doctor",
    ),
    "ORDINAL": (
        "tests.test_ordinals",
    ),
    "SALVAGE_VERIFY": (
        "tests.test_adversarial",
        "tests.test_artifacts_verify",
        "tests.test_safety_mvp",
    ),
    "DISCOVERY": (
        "tests.test_discovery",
    ),
    "PRIVACY": (
        "tests.test_issue_24369",
    ),
    "CONCURRENCY": (
        "tests.test_controller_script",
    ),
    "WINDOWS_SPECIFIC": (),
    "E2E_TIER1": (
        "tests.test_cli_mvp",
        "tests.test_real_current_session",
    ),
    "E2E_TIER2": (
        "tests.test_issue_14824",
        "tests.test_issue_37719",
        "tests.test_real_corpus",
    ),
    "SCALE_SOAK": (
        "tests.test_hardening",
    ),
    "PACKAGING": (),
    "HARNESS": (
        "tests.test_fixture_portability",
        "tests.test_gitstate",
        "tests.test_gitstate_hardening",
    ),
}

# ``materialize_fixture_git_repo`` temporarily creates ``.git`` below the
# committed ``fixtures/*/repo_actual`` snapshots.  Keep every shard touching
# those snapshots in one serial lane; an external CI matrix must not run this
# group concurrently.  Other non-empty shards are independent by construction.
SERIAL_GROUPS: Final[tuple[tuple[str, ...], ...]] = (
    ("E2E_TIER2", "PRIVACY", "HARNESS"),
)


def _available_test_modules() -> set[str]:
    return {
        f"tests.{path.stem}"
        for path in (ROOT / "tests").glob("test_*.py")
    }


def _validate_manifest() -> None:
    assigned: list[str] = [module for modules in SHARDS.values() for module in modules]
    duplicates = sorted({module for module in assigned if assigned.count(module) > 1})
    missing = sorted(_available_test_modules() - set(assigned))
    unknown = sorted(set(assigned) - _available_test_modules())
    if duplicates or missing or unknown:
        details: list[str] = []
        if duplicates:
            details.append(f"duplicate modules: {', '.join(duplicates)}")
        if missing:
            details.append(f"unassigned modules: {', '.join(missing)}")
        if unknown:
            details.append(f"unknown modules: {', '.join(unknown)}")
        raise SystemExit("Invalid test shard manifest (" + "; ".join(details) + ")")


def _source_env() -> dict[str, str]:
    env = os.environ.copy()
    source_path = str(ROOT / "src")
    existing = env.get("PYTHONPATH")
    env["PYTHONPATH"] = source_path if not existing else os.pathsep.join((source_path, existing))
    return env


def _print_shards() -> None:
    for name, modules in SHARDS.items():
        if modules:
            print(f"{name}: {', '.join(modules)}")
        else:
            print(f"{name}: (reserved; no repository tests currently assigned)")
    for group in SERIAL_GROUPS:
        print(f"SERIAL_GROUP: {', '.join(group)}")


def _run_shard(name: str) -> int:
    modules = SHARDS[name]
    if not modules:
        print(f"{name}: no tests currently assigned; refusing to report a pass", file=sys.stderr)
        return 2
    command = [sys.executable, "-m", "unittest", *modules, "-v"]
    print(f"Running {name} ({len(modules)} test modules)", flush=True)
    return subprocess.call(command, cwd=ROOT, env=_source_env())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="list shard membership and exit")
    parser.add_argument("--shard", choices=tuple(SHARDS), help="run one named shard")
    args = parser.parse_args(argv)
    _validate_manifest()
    if args.list:
        _print_shards()
        return 0
    if args.shard is None:
        parser.error("provide --shard NAME or --list")
    return _run_shard(args.shard)


if __name__ == "__main__":
    raise SystemExit(main())

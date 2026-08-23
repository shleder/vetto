from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

from .doctor import doctor_session
from .fixtures import materialize_fixture_git_repo
from .salvage import salvage_session
from .verify import verify_rescue


def _hash_tree(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for file in sorted(item for item in path.rglob("*") if item.is_file()):
        if ".git" in file.parts:
            continue
        digest = hashlib.sha256()
        with file.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
        result[str(file.relative_to(path)).replace("\\", "/")] = digest.hexdigest()
    return result


def run_fixture(fixture: Path, output_root: Path) -> dict[str, Any]:
    expected = json.loads((fixture / "expected.json").read_text(encoding="utf-8"))
    session = next((fixture / "source_session").glob("*.jsonl"))
    before = _hash_tree(fixture / "source_session")
    repo_before = _hash_tree(fixture / "repo_actual")
    started = time.perf_counter()

    with materialize_fixture_git_repo(fixture):
        doctor = doctor_session(session)
        salvage = salvage_session(session, doctor.transcript, doctor.status, doctor.findings, output_root, True)
        verify = verify_rescue(output_root, salvage.rescue_id)

    elapsed = time.perf_counter() - started
    after = _hash_tree(fixture / "source_session")
    original_untouched = before == after and salvage.original_untouched
    classification_ok = expected["doctor"] in doctor.findings
    expected_verify = expected.get("verify", "STATE_DIVERGED")
    if isinstance(expected_verify, (list, tuple, set)):
        verify_ok = verify.status in expected_verify
    else:
        verify_ok = verify.status == expected_verify
    handoff_size = Path(salvage.handoff_path).stat().st_size
    bounded = handoff_size < 100_000
    no_duplicate_edit = repo_before == _hash_tree(fixture / "repo_actual")
    passed = all([classification_ok, verify_ok, original_untouched, bounded, no_duplicate_edit, elapsed < 60])
    return {
        "fixture": fixture.name,
        "doctor_status": doctor.status,
        "findings": doctor.findings,
        "classification_ok": classification_ok,
        "salvage": True,
        "verify": verify.status,
        "verify_expected": expected_verify,
        "verify_ok": verify_ok,
        "no_duplicate_edit": no_duplicate_edit,
        "original_untouched": original_untouched,
        "bounded_handoff": bounded,
        "time_seconds": round(elapsed, 4),
        "result": "PASS" if passed else "FAIL",
        "rescue_id": salvage.rescue_id,
    }


def run_all(fixtures_root: str | Path, output_root: str | Path) -> dict[str, Any]:
    fixtures = Path(fixtures_root)
    output = Path(output_root)
    rows = [run_fixture(path, output) for path in sorted(fixtures.iterdir()) if path.is_dir()]
    passed = sum(row["result"] == "PASS" for row in rows)
    all_passed = passed == len(rows)
    return {"fixtures": rows, "passed": passed, "total": len(rows), "all_passed": all_passed, "poc_pass": all_passed}


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("fixtures", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(run_all(args.fixtures, args.output), indent=2))

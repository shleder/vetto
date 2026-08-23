"""Tier 1: Feature Coverage Test Suite (50 tests across 10 areas)."""
import sys
from pathlib import Path

_repo_root = Path(__file__).resolve().parent.parent.parent.parent
_src_dir = _repo_root / "src"
_e2e_dir = _repo_root / "tests" / "e2e"
if str(_src_dir) not in sys.path:
    sys.path.insert(0, str(_src_dir))
if str(_e2e_dir) not in sys.path:
    sys.path.insert(0, str(_e2e_dir))

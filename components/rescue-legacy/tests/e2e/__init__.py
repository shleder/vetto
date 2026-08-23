"""E2E test suite for Codex Rescue Alpha5."""
from __future__ import annotations

import sys
from pathlib import Path

# Ensure src/ is in sys.path for test discovery and direct test execution
_src_dir = Path(__file__).resolve().parent.parent.parent / "src"
if str(_src_dir) not in sys.path:
    sys.path.insert(0, str(_src_dir))

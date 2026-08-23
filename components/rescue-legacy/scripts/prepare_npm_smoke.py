from __future__ import annotations

import json
from pathlib import Path


def main() -> int:
    root = Path("build/npm-smoke")
    root.mkdir(parents=True, exist_ok=True)
    package = {
        "private": True,
        "name": "codex-rescue-smoke",
        "version": "0.0.0",
    }
    (root / "package.json").write_text(
        json.dumps(package, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(root.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

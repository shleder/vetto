from __future__ import annotations

import argparse
import json
import os
import shutil
from pathlib import Path


EXPECTED_VERSION = "0.1.0-alpha.7"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--template", required=True, type=Path)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    template = args.template.resolve()
    binary = args.binary.resolve()
    output = args.output.resolve()
    if not template.is_dir():
        raise SystemExit(f"platform template does not exist: {template}")
    if not binary.is_file():
        raise SystemExit(f"native binary does not exist: {binary}")

    package = json.loads((template / "package.json").read_text(encoding="utf-8"))
    if package.get("version") != EXPECTED_VERSION:
        raise SystemExit(
            f"platform package version mismatch: {package.get('version')} != {EXPECTED_VERSION}"
        )

    if output.exists():
        shutil.rmtree(output)
    shutil.copytree(template, output)
    bin_dir = output / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    target_name = "codex-rescue.exe" if binary.suffix.lower() == ".exe" else "codex-rescue"
    target = bin_dir / target_name
    shutil.copy2(binary, target)
    if os.name != "nt":
        target.chmod(target.stat().st_mode | 0o111)
    print(target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

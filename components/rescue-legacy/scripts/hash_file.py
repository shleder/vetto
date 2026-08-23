from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    path = args.path.resolve()
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    line = f"{digest.hexdigest()}  {path.name}\n"
    if args.output:
        args.output.write_text(line, encoding="utf-8")
    print(line, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

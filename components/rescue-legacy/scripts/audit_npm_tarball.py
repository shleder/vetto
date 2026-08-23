from __future__ import annotations

import argparse
import tarfile
from pathlib import Path


TOP_ALLOWED = {
    "package/package.json",
    "package/README.md",
    "package/bin/codex-rescue.js",
}
PLATFORM_ALLOWED_COMMON = {
    "package/package.json",
    "package/README.md",
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("tarball", type=Path)
    parser.add_argument("--kind", choices=("top", "platform"), required=True)
    args = parser.parse_args()

    tarball = args.tarball.resolve()
    with tarfile.open(tarball, "r:gz") as archive:
        members = [member for member in archive.getmembers() if member.isfile()]
        names = {member.name for member in members}
        if any(member.issym() or member.islnk() for member in archive.getmembers()):
            raise SystemExit("npm tarball contains a link entry")

    if args.kind == "top":
        unexpected = names - TOP_ALLOWED
        missing = TOP_ALLOWED - names
        if unexpected or missing:
            raise SystemExit(f"top package allowlist mismatch: unexpected={sorted(unexpected)} missing={sorted(missing)}")
    else:
        binaries = names - PLATFORM_ALLOWED_COMMON
        if len(binaries) != 1 or binaries.pop() not in {
            "package/bin/codex-rescue",
            "package/bin/codex-rescue.exe",
        }:
            raise SystemExit(f"platform package allowlist mismatch: {sorted(names)}")
        missing = PLATFORM_ALLOWED_COMMON - names
        if missing:
            raise SystemExit(f"platform package missing metadata: {sorted(missing)}")
    print("npm tarball allowlist: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

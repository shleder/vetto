"""PyInstaller entrypoint for the standalone Codex Rescue executable."""

from codex_rescue.cli import main


if __name__ == "__main__":
    raise SystemExit(main())

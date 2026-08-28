# vetto for VS Code

This extension launches an agent in VS Code's integrated terminal through the
locally installed `vetto` binary. Session JSONL and reports are stored in the
extension's private global-storage directory rather than the writable project
tree.

Commands:

- **vetto: Run Agent** — prompt for an agent command and run it with the
  configured profile/network/TUI settings.
- **vetto: Doctor** — show the effective platform tier and capabilities.
- **vetto: Install Shell & Git Hooks** — install transparent native shims (`vetto hook install`) to isolate subagents automatically.
- **vetto: Rescue Agent Session** — discover, diagnose, and checkpoint damaged session trees across Claude Code, Codex, and Cursor.
- **vetto: Refresh Events** — reload the latest 500 JSONL events in the vetto
  activity-bar view.
- **vetto: Open Last Report** — open the newest HTML report.

The extension does not bundle, download, elevate, or update vetto. Install the
CLI separately and configure `vetto.executable` if it is not on `PATH`.

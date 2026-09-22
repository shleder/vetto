# Vetto Agent Sandbox for VS Code

This extension provides seamless integration with **Vetto**, a daemon-less kernel-level sandbox and policy enforcement runtime for AI coding agents.

## Features

- **Status Bar Indicator**: Real-time monitoring of sandbox status. Click to open the latest audit report.
- **Run Sandboxed Tasks**: Wrap any terminal command within the Vetto sandbox directly from the command palette.
- **Diff Sessions**: Launch `vetto diff-sessions` directly in VS Code's integrated diff viewer.
- **Security Auditing**: Quickly open the post-session JSONL audit and security reports.

## Extension Settings

This extension contributes the following settings:

* `vetto.path`: Path to the `vetto` executable (default: `vetto`).
* `vetto.defaultProfile`: The default security profile (default: `default`).
* `vetto.enableNotifications`: Enable popup notifications for blocks and alerts.

## Commands

- `Vetto: Run Sandboxed Task` (`vetto.runSandboxed`)
- `Vetto: Show Sandbox Status` (`vetto.showStatus`)
- `Vetto: Diff Sessions` (`vetto.diffSessions`)
- `Vetto: Open Audit Report` (`vetto.openAudit`)

## Requirements

The `vetto` CLI must be installed and available in your `PATH` or configured via `vetto.path`.

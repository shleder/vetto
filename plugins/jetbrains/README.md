# vetto for JetBrains IDEs

The `vetto` tool window runs non-interactive agent commands through the local
vetto binary and displays captured output. It also exposes `vetto doctor` and
opens the newest HTML report.

Session logs and reports live under `~/.vetto/jetbrains`, outside the writable
project directory. The plugin never downloads, updates, elevates, or publishes
vetto; install the CLI separately.

Build verification uses the IntelliJ Platform Gradle Plugin. No Marketplace
publication task is part of the repository workflow.

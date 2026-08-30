# Vetto VS Code Extension

Run any VS Code workspace task or terminal command inside the kernel-enforced **Vetto Sandbox** with a single keystroke.

---

## Features

- **Command: `Vetto: Run Task Sandboxed`**: Interactively select any task configured in your workspace's `.vscode/tasks.json` and execute it wrapped inside `vetto`.
- **Configurable Profiles**: Select default security policy profile (`default`, `strict`, `audit`, `permissive`) in VS Code settings.
- **Network Confinement**: Apply network allowlists or strict offline enforcement to task runners.

---

## Extension Settings

| Setting | Default | Description |
|---|---|---|
| `vetto.executablePath` | `"vetto"` | Path to the `vetto` CLI binary |
| `vetto.defaultProfile` | `"default"` | Default security policy profile |
| `vetto.defaultNet` | `"off"` | Default network isolation mode |

---

## Building and Packaging (`.vsix`)

This extension does not require publishing to the Marketplace; you can build and install it locally using `vsce`:

### 1. Install `vsce`
```bash
npm install -g @vscode/vsce
```

### 2. Package the Extension
```bash
cd vscode
npx @vscode/vsce package
```
This produces `vetto-vscode-0.2.5.vsix`.

### 3. Install in VS Code
```bash
code --install-extension vetto-vscode-0.2.5.vsix
```

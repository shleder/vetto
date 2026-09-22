# Windows Sandbox (`--windows-sandbox`)

Vetto supports Windows Sandbox (disposable microVM) as an opt-in alternative to AppContainer process sandboxing on Windows 10/11 Pro and Enterprise editions.

## Architecture & Guarantees

Unlike AppContainer LPAC, which is a process-level security token isolation within the host OS kernel, Windows Sandbox generates a temporary hardware-virtualized environment based on Hyper-V container technology:

1. **Disposable Lifecycle**: Every session runs inside a fresh, pristine Windows instance and is completely discarded upon exit.
2. **Deterministic Folder Sharing**: The workspace directory is mapped into the container environment.
3. **Network Mode Conformance**: When `--net=off` is active, network adapter pass-through is disabled in the generated `.wsb` profile (`<Networking>Disable</Networking>`).
4. **Zero Host Elevation**: The launcher checks hardware virtualization firmware and Windows feature presence without requesting UAC escalation.

## Usage

```bash
# Run command inside Windows Sandbox
vetto --windows-sandbox -- npm test

# Run with network disabled
vetto --windows-sandbox --net=off -- cargo build
```

## Requirements

- Windows 10 Pro/Enterprise build 18305 or Windows 11
- Virtualization enabled in BIOS/UEFI (`PF_VIRT_FIRMWARE_ENABLED`)
- "Windows Sandbox" optional Windows feature enabled

# Uniform runtime

One enforcement contract on every OS: the default requires Tier-1 —
direct Linux kernel enforcement, or Tier-1 inside a VM. Legacy process
backends never apply implicitly.

## How it works

```
host vetto (macOS / Windows)
  1. VM provision   — start (or reuse) the backend VM
  2. sync workspace — copy the project into the VM (host secrets excluded)
  3. exec linux vetto — run the Linux Tier-1 stack inside the VM
                        (Landlock + seccomp + mount/PID/net namespaces)
  4. sync back       — copy results out of the VM
  5. teardown        — stop the VM (disposable) or leave a clean reusable image
```

Enforcement always happens inside the Linux VM; the host side only
orchestrates provision/sync/teardown and never executes the agent itself.

## Requirements

| Backend (`--backend`) | Host | Requirements |
| :--- | :--- | :--- |
| `mac-vm` (default on macOS) | macOS | Virtualization.framework-capable Mac + VM image with Linux vetto (owned by `feat/uniform-mac-vm`) |
| `wsl2` (default on Windows) | Windows | WSL2 enabled + Linux distro with vetto installed (owned by `feat/uniform-win-wsl2`) |
| direct (default on Linux) | Linux | Landlock ABI v1+ kernel, unprivileged userns |

`--backend auto` (the default) resolves to direct / `mac-vm` / `wsl2` by OS.
`--backend process` selects the deprecated legacy process backend explicitly.
`--backend win-sandbox` remains an opt-in disposable Hyper-V VM on Windows.

## Fail-closed table

No silent downgrade, ever: a missing VM runtime exits `103`
(`VETTO_ERR_FAIL_CLOSED`) and `vetto doctor` prints the fix.

| Condition | `vetto doctor` says | Session action |
| :--- | :--- | :--- |
| macOS, no VM runtime / image | `default enforcement: mac-vm (tier-1 in VM)` + missing-VM reason | fail closed: install/provision the VM image, or explicit `--backend process` (deprecated legacy) |
| Windows, WSL2 / distro missing | `default enforcement: wsl2 (tier-1 in VM)` + missing-distro reason | fail closed: install the WSL2 distro, or explicit `--backend process` (deprecated legacy) |
| Linux, Landlock / userns missing | `chosen tier: NONE — fail-closed` + kernel reason | fail closed: upgrade kernel / enable Landlock+userns |
| `--backend mac-vm` on non-macOS | only available on macOS | fail closed: use `--backend auto` |
| `--backend wsl2` on non-Windows | only available on Windows (WSL2 host) | fail closed: use `--backend auto` |
| unknown `--backend` name | `unknown backend '<name>'; valid backends: auto, process, mac-vm, wsl2, win-sandbox` | fail closed: pick a valid name or omit the flag |

Until `feat/uniform-mac-vm` / `feat/uniform-win-wsl2` merge, explicit
`--backend mac-vm` / `--backend wsl2` on their home OS fail closed with
`not yet integrated`; the matrix, defaults, and reasons above already hold.

# Public Red-Team Evaluation Report

[![Sandbox Status: 100% Repelled](https://img.shields.io/badge/Security_Boundary-100%25_Repelled-brightgreen)](#)
**Last Automated Run:** `2026-08-30 12:00:00 UTC`  
**Verdict:** `SECURE_FAIL_CLOSED`  
**Attacks Evaluated:** `7` | **Repelled:** `7` | **Bypasses:** `0`

---

## Adversarial Attack Scenarios

| Attack Category | Scenario Description | Expected Outcome | Observed Outcome | Status |
|---|---|---|---|---|
| `filesystem_traversal` | Secret file read via relative traversal (../../.ssh/id_rsa) | `DENIED` | `DENIED` | ✅ REPELLED |
| `symlink_escape` | Symlink pointing outside project write root | `DENIED` | `DENIED` | ✅ REPELLED |
| `secret_masking` | Direct open of masked project .env file | `EMPTY_OR_EACCES` | `EMPTY_OR_EACCES` | ✅ REPELLED |
| `network_exfiltration` | Raw TCP connect outside broker allowlist | `ENETUNREACH_OR_EACCES` | `ENETUNREACH_OR_EACCES` | ✅ REPELLED |
| `ptrace_injection` | Cross-process memory attachment via ptrace/process_vm_writev | `EPERM` | `EPERM` | ✅ REPELLED |
| `env_theft` | Inheritance of unallowlisted host environment variables (AWS_SECRET_ACCESS_KEY) | `STRIPPED` | `STRIPPED` | ✅ REPELLED |
| `resource_exhaustion` | Fork bomb / unbounded PID allocation | `CAPPED` | `CAPPED` | ✅ REPELLED |

---

## Methodology & Security Boundaries
All attacks are run automatically under the strict-wins policy. The evaluation tests:
1. **Filesystem Traversal**: Attempts to access parent directories, relative traversal, and symlink breakouts.
2. **Secret Masking**: Direct reads against `.env`, `~/.ssh`, `~/.aws`, and masked credential stores.
3. **Network Egress**: Raw socket allocation, DNS rebinding, and connections outside allowlisted broker targets.
4. **Kernel & Memory Hardening**: `ptrace`, `process_vm_writev`, `userfaultfd`, and eBPF system call injection.
5. **Environment Theft**: Attempts to inherit unallowlisted host environment variables.

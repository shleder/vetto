# Phase B: Consolidated Execution-Path Map and Existing Checks Registry

## 1. Unified Execution Path Map

```
[Entrypoint (CLI / MCP / Multi)]
       │
       ▼
[Policy Formulation / Intent]
       │
       ▼
[PolicyCompiler::compile_effective]
       │
       ▼
[UnsealedSecurityContract -> BLAKE3 compute_digest -> .seal()]
       │
       ▼
[UnpreparedProductionExecution::new]
       │
       ▼
[prepare() -> freeze_production_contract -> FrozenSpec (SHA-256) -> ExecutionIdentity]
       │
       ▼
[PreparedProductionExecution (FSM: Prepare)]
       │
       ▼
[spawn() (FSM: Spawn -> Enforce -> Observe)]
       │
       ▼
[OS Backend Lowering (Landlock, Seccomp, Namespaces, Rlimits, Subreaper)]
       │
       ▼
[Attacker Action / Probe In Confined Child]
       │
       ▼
[Evidence Collection]
  - HOST_FACT: exit code, /proc/<pid>/status (Seccomp, NoNewPrivs), tripwire hashes, subreaper sweep, host control FIFO.
  - CONSTRAINED: kernel errno / diagnostic channel (fails only).
  - SELF_REPORT: child stdout/stderr, child marker files (CANNOT give PASS).
       │
       ▼
[Oracle & Gate Evaluation]
  - oracle::judge: requires HOST_FACT, verified identity, intact fixtures.
  - evaluate_gate: enforces non-empty suite, zero inconclusive blockers (I1-I6), mandatory canaries (VFS-TRAV-001, ENV-LEAK-001, PROC-ESC-001), and min_pass_per_category.
```

## 2. Existing Checks by Category (DO NOT DUPLICATE)

### Filesystem & Traversal
- `VFS-TRAV-001` (registry.rs:195, FsRead blocker canary)
- `deny-path` (verify.rs:330, 336, 340)
- `write-outside` (verify.rs:370, 374)
- `test_linux_fs_read_deny_001` (verify_ng_linux_enforce.rs:191)
- `test_linux_fs_write_deny_001` (verify_ng_linux_enforce.rs:226)
- `test_linux_fs_escape_001` (verify_ng_linux_enforce.rs:256)
- `test_linux_fs_root_isolation_001` (verify_ng_linux_enforce.rs:291)
- `adv_dotdot_escape_of_allow_root_is_denied` (adv_isolation.rs:52)
- `adv_dotdot_evasion_of_deny_is_still_denied` (adv_isolation.rs:73)
- `adv_slash_confusables_stay_denied` (adv_isolation.rs:100)
- `adv_symlink_parent_escape_is_denied` (adv_isolation.rs:123)
- `adv_case_variant_is_not_confused` (adv_isolation.rs:152)

### Secrets
- `ENV-LEAK-001` (registry.rs:243, Secrets blocker canary)
- `EVIDENCE-REDACT-001` (registry.rs:285)
- `adv_proxy_secrets_stripped_but_neighbors_kept` (adv_isolation.rs:171)
- `adv_proxy_beats_explicit_passthrough` (adv_isolation.rs:184)
- `adv_proxy_env_extra_merge_must_be_restripped` (adv_isolation.rs:205)

### Environment
- `ENV-POISON-001` (registry.rs:154, Spawn blocker)
- `trap_env_poison_fails_blockers` (verify_ng_traps.rs:160)

### Process Containment
- `PROC-ESC-001` (registry.rs:227, Proc blocker canary)
- `HANG-GRANDCHILD-001` (registry.rs:179)
- `CLEANUP-SIGKILL-001` (registry.rs:269)
- `setsid_daemon_escape` (redteam.rs:85)
- `test_linux_proc_escape_001` (verify_ng_linux_enforce.rs:436)
- `test_linux_grandchild_001` (verify_ng_linux_enforce.rs:470)
- `test_linux_tree_kill_001` (verify_ng_linux_enforce.rs:506)
- `test_linux_orphan_001` (verify_ng_linux_enforce.rs:539)
- `test_process_tree_extinction_theorem_cases` (phase4_enterprise_runtime.rs:258)

### Network
- `NET-DNS-IPV6-001` (registry.rs:211, Net blocker)
- `net-loopback` (verify.rs:361)
- `raw_socket_packet` (redteam.rs:249)
- `test_linux_net_deny_001` (verify_ng_linux_enforce.rs:338)
- `test_linux_net_escape_001` (verify_ng_linux_enforce.rs:371)
- `test_linux_net_allow_001` (verify_ng_linux_enforce.rs:405)
- `adv_broker_domain_allowlist_fail_closed` (adv_isolation.rs:221)

### Contract Tampering & Identity Binding
- `phase1_production_preparation_receives_sealed_contract` (production.rs:2021)
- `phase1_invalid_contract_never_prepares_capabilities` (production.rs:2108)
- `phase1_contract_tamper_rejected_before_spawn` (production.rs:2224)
- `phase1_caller_policy_cannot_change_canonical_backend_input` (production.rs:2317)
- `phase1_production_audit_binds_actual_contract` (production.rs:2380)
- `test_prod_backend_fail_closed_001_no_spawn` (production.rs:2439)
- `seal_and_verify_digest` (contract.rs:305)
- `deterministic_digest` (contract.rs:323)
- `test_frozen_identity_001_registry_hash_binds_semantics` (verify_ng_traps.rs:541)
- `TEST-HOST-EVIDENCE-REPLAY-001` (verify_ng_host_evidence.rs:381)
- `TEST-HOST-CONTROL-WRONG-SCENARIO-001` (verify_ng_host_evidence.rs:452)
- `TEST-HOST-CONTROL-WRONG-REGISTRY-001` (verify_ng_host_evidence.rs:493)

### Evidence Model & Suite Gates
- `ORACLE-DECEIT-001` (registry.rs:120)
- `CONTROL-SPLIT-001` (registry.rs:132)
- `FIXTURE-MUTATE-001` (registry.rs:142)
- `GATE-VACUUM-001` (registry.rs:168)
- `evaluate_gate` (exit.rs:70)
- `trap_gate_vacuum_empty_suite_fails` (verify_ng_traps.rs:175)
- `trap_gate_requires_fs_write_minimum` (verify_ng_traps.rs:420)

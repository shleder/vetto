# Codex Derived State Recovery Contract

**Laboratory Specification & Primary-Source Audit**  
**Audited Binary:** Official `@openai/codex` / `codex-cli 0.147.0` (x86_64)  
**Database Schema Version:** `state_5.sqlite` (SQLx migration v5)  
**Date:** 2026-08-18

---

## 1. Authoritative Upstream Findings

### 1.1 Authoritative Upstream Paths
* **CLI Entrypoint:** `codex` (Rust binary wrapping App Server and TUI).
* **App Server:** `codex app-server --stdio` (JSON-RPC stdio daemon).
* **Database Storage:** `$CODEX_HOME/state_5.sqlite`, `$CODEX_HOME/goals_1.sqlite`, `$CODEX_HOME/logs_2.sqlite`, `$CODEX_HOME/memories_1.sqlite`, `$CODEX_HOME/queue_1.sqlite`.
* **Rollout Storage:** `$CODEX_HOME/sessions/rollout-*.jsonl` and `$CODEX_HOME/archived_sessions/rollout-*.jsonl`.

### 1.2 Supported Recovery Entrypoints
* **Upstream Re-indexing Command:** **NONE**. Upstream `codex-cli 0.147.0` exposes no CLI subcommand or App Server RPC method to backfill, reconstruct, or scan orphaned rollout files into `state_5.sqlite:threads`.
* **App Server Startup Behavior:** Initializing `codex app-server` against a missing `state_5.sqlite` successfully executes SQLx migrations to create empty database tables, but does **not** scan `$CODEX_HOME/sessions` or populate `threads`. `thread/list` returns `{"data": [], "nextCursor": null}`.
* **CLI Doctor Capability:** `codex doctor` reports configuration, daemon socket status, and update status, but does not perform derived state index reconstruction.

### 1.3 Supported Database Migrations
* Codex initializes SQLite schemas via embedded SQLx migrations:
  * `state_5.sqlite`: Tables `threads` (34 columns), `thread_dynamic_tools`, `backfill_state`, `thread_spawn_edges`, `remote_control_enrollments`, `external_agent_config_imports`, `thread_sections`.
  * `goals_1.sqlite`: Tables `thread_goals`, `thread_goal_continuation_deferrals`.
  * `logs_2.sqlite`: Table `logs`.
  * `memories_1.sqlite`: Tables `stage1_outputs`, `jobs`.
  * `queue_1.sqlite`: Table `queued_items`.

---

## 2. Thread Metadata Audit

### 2.1 Fields Derivable from Canonical Rollout (`session_meta` / JSONL header)
* `id` (Session / Thread UUID)
* `rollout_path` (Canonical absolute path on filesystem)
* `created_at` / `created_at_ms` (Extracted from initial record timestamp)
* `updated_at` / `updated_at_ms` (Extracted from final record timestamp)
* `source` / `thread_source` (Origin label if declared in `session_meta`, e.g. `"cli"`, `"vscode"`)
* `model_provider` (If declared in `session_meta`, e.g. `"openai"`)
* `cwd` (Working directory if declared in `session_meta`)
* `title` (Extracted from initial turn user prompt)
* `first_user_message` (Extracted from initial turn text)
* `git_sha` / `git_branch` / `git_origin_url` (If present in git context block)

### 2.2 Fields NOT Derivable from Canonical Rollout (Authoritative Metadata Unavailable)
* `sandbox_policy` (e.g. `read-only`, `workspace-write`, `danger-full-access` — set at runtime by user CLI invocation)
* `approval_mode` (e.g. `auto`, `untrusted`, `on-request`, `never` — set at runtime by user flag)
* `memory_mode` (e.g. `enabled`, `disabled` — runtime feature configuration)
* `tokens_used` (Accumulated accounting counter maintained by server process)
* `recency_at` / `recency_at_ms` (UI access ordering state)
* `thread_section_id` / `section_position` (UI sidebar organization state)
* `is_pinned` (UI pinned state)
* `history_mode` (Internal migration flag)

---

## 3. Policy: No Guessed State Mutation

### 3.1 Safe Recovery Method
1. **Read-Only Diagnosis & Forensics:** Rescue identifies rollouts that exist on disk but lack SQLite registration (`UNINDEXED_IN_SQLITE`), reporting exact file locations, record counts, and byte integrity.
2. **Pure Source Salvage:** Rescue creates clean durable JSONL copies (`codex-rescue salvage --fork`) without modifying or fabricating SQLite database files.
3. **Safe Portable Export/Import:** Portable packages import canonical rollout JSONL streams into the target `$CODEX_HOME/sessions/` directory.
4. **Hold on Direct Database Fabrication:** Because Codex does not expose an official backfill API and critical columns cannot be authoritatively known, Rescue **strictly holds direct SQLite reconstruction**.

### 3.2 Unsupported Direct Mutations (PROHIBITED)
* Prohibited: `CREATE TABLE IF NOT EXISTS threads (...)` with synthetic schema.
* Prohibited: `INSERT OR REPLACE INTO threads (...)` with guessed defaults (`sandbox_policy='read-only'`, `approval_mode='auto'`).
* Prohibited: Overwriting healthy metadata or fabricating missing foreign key relations (`thread_sections`, `thread_goals`).

---

## 4. Status
* **CODEX_OWNED_RECOVERY_PATH_FOUND:** `NO`
* **REAL_DERIVED_REPAIR:** `NOT_READY` / `HOLD`
* **READ_ONLY_TIER_1:** `READY`
* **MUTATION_TIER_1:** `HOLD`

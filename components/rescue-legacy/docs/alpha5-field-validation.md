# Alpha5 field validation traceability

This document maps public `openai/codex` field evidence to Codex Rescue Alpha5 behavior and regression coverage. Upstream reports are not treated as Rescue defects unless they expose a Rescue false-positive/false-healthy boundary.

Raw rollouts/databases are intentionally not copied here. They can contain private prompts, paths, tool output, credentials, and media.

## Classification definitions

- `FIXED_IN_CODE_UNVERIFIED` — Alpha5 code/regression exists, but the current branch head has not yet completed the required exact-head CI qualification.
- `VERIFIED_BY_CI` — the referenced behavior has passed the required CI on the exact qualifying commit.
- `ALREADY_FIXED_IN_A4` — authoritative Alpha4 already handles the specific Rescue defect.
- `DETECTED_BOUNDED` — Rescue safely detects/bounds persisted evidence without claiming to fix the upstream defect.
- `OUT_OF_SCOPE_UPSTREAM` — the reported failure is in an upstream transport/UI/remote/service path Rescue cannot observe or repair; it is retained as a negative control against fabricated local-corruption claims.

Exact current-head qualification is recorded by GitHub Actions and the Alpha5 release handoff. Rows stay conservative rather than being rewritten after every documentation-only commit.

## Field evidence map

| Issue | Field evidence used | Rescue version exercised | Rescue boundary | Alpha5 implementation | Regression / control | Classification |
|---|---|---|---|---|---|---|
| [#31113](https://github.com/openai/codex/issues/31113) | Persisted tool chain can end without expected durable output/result. | N/A | Missing output must not become HEALTHY or a fabricated non-execution claim. | Bounded call/output correlation. | tool-correlation cases in `tests/test_alpha5_diagnostics.py` | `DETECTED_BOUNDED` |
| [#38629](https://github.com/openai/codex/issues/38629) | Multiple app-server writers can append interleaved persisted history. | N/A | One incoherent stream must not be called healthy. | Explicit persisted writer-identity A-B-A interleave detection; no repair. | `test_explicit_a_b_a_writer_interleave_detected` | `FIXED_IN_CODE_UNVERIFIED` |
| [#24550](https://github.com/openai/codex/issues/24550) | ~703 MB rollout; image-heavy compacted history. | N/A | Large records/media must remain bounded. | Bounded physical-record scan, media indicator, no Base64 decode. | `test_large_record_scan_is_bounded_and_reports_inline_media` | `DETECTED_BOUNDED` |
| [#34337](https://github.com/openai/codex/issues/34337) | Rollout stores can reach tens/hundreds of GiB. | N/A | Analysis must not scale as whole-file memory. | Linear bounded scans and aggregate diagnostics. | large-record/correlation hardening tests | `DETECTED_BOUNDED` |
| [#30779](https://github.com/openai/codex/issues/30779) | Persisted subagent/start history can outlive execution. | N/A | Historical start is not proof of a live agent. | Persisted marker separated from unavailable live state. | `test_lifecycle_never_claims_historical_start_is_live` | `FIXED_IN_CODE_UNVERIFIED` |
| [#20864](https://github.com/openai/codex/issues/20864) | Valid rollout inventory can disagree with derived/index state. | N/A | DB cannot be the sole discovery truth. | Filesystem-first discovery with read-only DB enrichment/mismatch. | rollout-without-row and DB-only tests | `FIXED_IN_CODE_UNVERIFIED` |
| [#38855](https://github.com/openai/codex/issues/38855) | Persisted response item ID prefix can conflict with concrete type. | N/A | Strong invalid identity must block HEALTHY. | Current upstream `ResponseItem::id_prefix()` mapping with legacy compatibility. | valid/invalid/missing/legacy/future ID tests | `FIXED_IN_CODE_UNVERIFIED` |
| [#23930](https://github.com/openai/codex/issues/23930) | UI can show stale activity from historical persistence. | N/A | Rescue must not assert current running state. | Historical lifecycle statement; live state unavailable. | lifecycle tests | `FIXED_IN_CODE_UNVERIFIED` |
| [#35463](https://github.com/openai/codex/issues/35463) | Parent/subagent history can be duplicated during normal multi-agent work. | N/A | Duplication alone is not concurrent-writer corruption. | Writer finding requires explicit writer identity/interleave. | `test_normal_subagent_metadata_is_not_writer_corruption` | `FIXED_IN_CODE_UNVERIFIED` |
| [#13724](https://github.com/openai/codex/issues/13724) | Encrypted-content failures observed around account/org changes. | N/A | Ciphertext alone cannot prove account/key mismatch. | Format-only opaque classification; no decrypt/root-cause assertion. | opaque-format tests | `FIXED_IN_CODE_UNVERIFIED` |
| [#36704](https://github.com/openai/codex/issues/36704) | `ocx1:` reported as foreign/proxy persisted marker. | N/A | Distinguish only strongly supported envelope classes. | `foreign_ocx1`, legacy envelope, unknown/malformed opaque classes. | opaque-format tests | `FIXED_IN_CODE_UNVERIFIED` |
| [#38787](https://github.com/openai/codex/issues/38787) | `thread/resume` reconstruction is expensive on ~22k-item active histories; follow-up reports show long history strongly amplifies iPad failures but fresh threads can still occasionally freeze. | N/A | Rescue does not fix Remote resume/UI performance and must not encode `large rollout == mobile crash cause`. | Bounded local scanning; large-history size is evidence/pressure only, not a causal mobile verdict. | bounded scan/correlation tests; existing healthy-local controls | `OUT_OF_SCOPE_UPSTREAM` + `DETECTED_BOUNDED` |
| [#38613](https://github.com/openai/codex/issues/38613) | New sessions can briefly have zero-byte rollout. | N/A | Transient write state must not become corruption certainty. | zero/header-only => `INCOMPLETE_ROLLOUT`; changed scan => `ACTIVE_WRITE_UNCERTAIN`. | incomplete/changed-during-read tests | `FIXED_IN_CODE_UNVERIFIED` |
| [#33796](https://github.com/openai/codex/issues/33796) | Multi-GB rollouts occur in field. | N/A | Bounded inspection only. | Bounded allocation; aggregate counts; no media decode. | large-record hardening | `DETECTED_BOUNDED` |
| [#38856](https://github.com/openai/codex/issues/38856) | Remote compaction/service failure. | N/A | Upstream service failure is not local repair scope. | README/diagnostics do not claim remote-compaction repair. | existing compaction/rollout tests | `OUT_OF_SCOPE_UPSTREAM` |
| [#33493](https://github.com/openai/codex/issues/33493) | 4.16 GB image-heavy rollout with repeated compactions. | N/A | Storage/compaction pressure only. | aggregate compaction/media diagnostics. | large-record test | `DETECTED_BOUNDED` |
| [#35746](https://github.com/openai/codex/issues/35746) | Projection boundary can replay an ordinal before expected ordinal. | N/A | Projection wedge must prevent false HEALTHY. | Read-only projection parity detects supported replay shape. | `test_replayed_boundary_ordinal_is_detected_conservatively` | `FIXED_IN_CODE_UNVERIFIED` |
| [#31433](https://github.com/openai/codex/issues/31433) | Valid active/archived rollouts can be absent from `state_5.sqlite`; Windows/WSL path variants matter. | N/A | DB-only discovery is insufficient. | Filesystem truth, archived discovery, path normalization. | discovery/path tests | `FIXED_IN_CODE_UNVERIFIED` |
| [#34863](https://github.com/openai/codex/issues/34863) | 10.2 GB rollout; sampled compacted records tens of MB with inline PNG. | N/A | Analyzer itself must remain bounded. | Bounded line draining and aggregate-only media diagnostics. | large-record test | `DETECTED_BOUNDED` |
| [#34446](https://github.com/openai/codex/issues/34446) | Valid rollout/DB row can have empty preview/user message and disappear from UI inventory. | N/A | Preview cannot be a discovery prerequisite. | Discovery surfaces rollout independent of preview. | `test_empty_preview_and_first_user_message_do_not_hide_rollout` | `FIXED_IN_CODE_UNVERIFIED` |
| [#38792](https://github.com/openai/codex/issues/38792) | Projection DB cursor can say next ordinal N while canonical boundary is N+1; cursor may also point mid-record. | N/A | Strong stable mismatch is wedge; ambiguous boundary stays unknown. | N→N+1 => `WEDGED_PROJECTION`; mid-record => fail-closed unknown; no writes. | projection N+1/mid-record tests | `FIXED_IN_CODE_UNVERIFIED` |
| [#32976](https://github.com/openai/codex/issues/32976) | Durable side effects can exist while visible/persisted transcript omits expected tool history. | N/A | Missing persisted output cannot prove non-execution. | Unfinished/unknown correlation only. | missing-output wording test | `FIXED_IN_CODE_UNVERIFIED` |
| [#32974](https://github.com/openai/codex/issues/32974) | Windows CLI can exit while waiting on tool/PostToolUse and leave no matching result/terminal event. | N/A | Distinct from #32976; persisted tail only. | Existing unfinished-tool/truncated-tail diagnostics. | unfinished/incomplete-tail coverage | `DETECTED_BOUNDED` |
| [#38889](https://github.com/openai/codex/issues/38889) | Fresh CLI 0.147 thread reportedly fails remote/iOS hydration with “Error loading messages / Codex connection was invalidated” while the same local persisted rollout remains usable in CLI/Desktop and deterministic local scan is clean. | N/A | **Negative control:** remote/mobile hydration failure is not evidence of local rollout corruption. Rescue cannot observe remote hydration state and must not fabricate a local finding from it. | No transport inference added. `HEALTHY` remains narrowly scoped to observable persisted structure; README explicitly says it is not proof of remote/UI health. | Existing healthy-doctor and healthy-projection controls; no remote-state simulation because Rescue has no such input. | `OUT_OF_SCOPE_UPSTREAM` |
| [#38846](https://github.com/openai/codex/issues/38846) | CLI 0.147 WebSocket close code 1009 / Message Too Big on a long thread; same oversized serialized request is retried before HTTPS fallback; byte cap can be hit before token auto-compaction threshold. | N/A | Transport retry/compaction policy is upstream. Large persisted records are useful boundary evidence but do not prove the exact outbound WS request size. | Rescue reports `OVERSIZED_PAYLOAD`/large-history aggregates without claiming to repair WebSockets or derive a definitive transport root cause. | oversized-record and large-history bounded tests | `OUT_OF_SCOPE_UPSTREAM` + `DETECTED_BOUNDED` |

## August 18 field-evidence addendum

| Issue | New field evidence | Alpha5 decision | Regression / safety boundary | Classification |
|---|---|---|---|---|
| [#38395](https://github.com/openai/codex/issues/38395) | A quickly aborted submitted prompt can be visible in the TUI while never becoming a durable rollout `response_item`. | Add `INTERRUPTED_INPUT_NOT_DURABLE` only when the retained bounded event window shows `task_started` → abort/interruption before a conservative durable submitted-user marker. | `tests/test_alpha5_field_hardening.py`; finding explicitly says absent prompt text cannot be reconstructed. | `FIXED_IN_CODE_UNVERIFIED` |
| [#38781](https://github.com/openai/codex/issues/38781) | A pre-repair WSL→Windows rollout was structurally healthy while saved `/mnt/d/...` execution context was interpreted as an invalid Windows-native path. | Preserve transcript-health semantics and add read-only workspace portability evidence; `WORKSPACE_CONTEXT_MISMATCH` requires both path-family conflict and inaccessible saved cwd. | WSL/Windows portability tests; no persisted path rewrite. | `FIXED_IN_CODE_UNVERIFIED` |
| [#38761](https://github.com/openai/codex/issues/38761) | After rollout migration, `session_index.jsonl` can retain the user-facing name while paginated SQLite `threads.name` is null and the name disappears from read/list/search. | Add `THREAD_NAME_METADATA_DIVERGED` from bounded index + read-only state DB evidence. | Raw thread name and name digest are never emitted; only presence and length are retained. | `FIXED_IN_CODE_UNVERIFIED` |
| [#38762](https://github.com/openai/codex/issues/38762) | Migrated persisted subagent can retain raw child-local history while `subagent_history_start_ordinal` is stamped at EOF, making derived history empty. | Add narrow `SUBAGENT_HISTORY_BOUNDARY_SUSPECT` only for the exact zero-based paginated EOF-boundary shape. | No SessionMeta rewrite; no data-loss claim; future/non-contiguous ordinal schemes remain unclassified. | `FIXED_IN_CODE_UNVERIFIED` |
| [#38234](https://github.com/openai/codex/issues/38234) | Lossy app-server event delivery can leave a durable call without a corresponding client-executed result. | No new detector: this strengthens the existing rule that a missing output means unfinished/unknown execution state, not proof of non-execution. | Existing tool-correlation tests and wording remain authoritative. | `DETECTED_BOUNDED` |
| [#31198](https://github.com/openai/codex/issues/31198), [#34268](https://github.com/openai/codex/issues/34268) | Current builds still produce multi-GiB subagent rollouts and hundreds of GiB aggregate persisted history dominated by repeated compacted/inherited payloads. | No third full scan. Existing Alpha5 bounded physical-size/media/compaction aggregates remain the correct evidence surface. | Large storage growth is pressure evidence, not a transcript-corruption or upstream-root-cause verdict. | `DETECTED_BOUNDED` |
| [#37042](https://github.com/openai/codex/issues/37042) | More current-build reproductions show durable child completion while Desktop cold-hydrates historical children as Running/Active. | No duplicate code path: existing Alpha5 lifecycle statement already separates persisted historical markers from unavailable live state. | `test_lifecycle_never_claims_historical_start_is_live`. | `FIXED_IN_CODE_UNVERIFIED` |
| [#37403](https://github.com/openai/codex/issues/37403) | Current Desktop/VS Code/iOS Remote paths can fail because another healthy surface owns the thread writer. | Negative control only. Writer ownership/handoff is upstream runtime state and is not rollout corruption. | Rescue does not delete locks or claim to fix writer leases. | `OUT_OF_SCOPE_UPSTREAM` |

## Alpha4 baseline audit

The authoritative Alpha4 implementation was inspected before Alpha5 edits. These are not reintroduced as Alpha5 “new fixes”:

- valid `mcp_tool_call_end` compatibility — `ALREADY_FIXED_IN_A4`;
- unavailable/non-Git repository evidence not being asserted as `REPO_STATE_DIVERGED` — `ALREADY_FIXED_IN_A4`;
- bounded persisted paginated ordinal reuse detection — `ALREADY_FIXED_IN_A4`.

Alpha5 extends these areas but does not rewrite the released Alpha4 tag or release.

## Primary upstream source anchors

- `codex-rs/thread-store/src/local/thread_history.rs` and `thread_history_materialization.rs`: projection state, byte offset, next ordinal.
- `codex-rs/protocol/src/models.rs`: `ResponseItem::id_prefix()`.
- `codex-rs/protocol/src/response_item_id.rs`: prefixed IDs plus legacy deserialization compatibility.
- `codex-rs/protocol/src/protocol.rs`: current event variants.

Unknown future operational schema is never whitelisted from naming guesses.

## Qualification boundary

The exact branch head must pass the required GitHub Actions before release. A previous green SHA does not qualify a later SHA. Documentation-only evidence changes do not retroactively change the behavior of an earlier tested binary, but release authorization is always tied to the current exact source SHA recorded in `docs/alpha5-release-handoff.md` and GitHub Actions.

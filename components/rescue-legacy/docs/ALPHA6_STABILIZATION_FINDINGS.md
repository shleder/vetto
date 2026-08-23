# Alpha6 stabilization findings

## `WINDOWS_ROLLOUT_PATH_IDENTITY_DIVERGENCE`

Codex Rescue emits this finding only when read-only evidence establishes that a discovered Windows rollout and the Codex thread-store `rollout_path` identify the same logical path while crossing the Win32 extended-length namespace boundary, for example `C:\...\rollout.jsonl` versus `\\?\C:\...\rollout.jsonl` (including the corresponding UNC form).

The finding is a **derived/thread-store consistency diagnosis**, not source corruption. The JSONL rollout can remain structurally healthy while archive, resume, heartbeat, or other Codex thread-store operations fail upstream because the persisted path spelling and the runtime/discovered spelling diverge.

Rescue does not repair this state. SQLite is opened read-only; Rescue does not update `threads.rollout_path`, strip `\\?\`, archive/unarchive sessions, rename rollouts, or otherwise rewrite Codex-owned state. Ambiguous device paths, unsafe extended-path spellings, unreadable databases, and path identities that cannot be established safely remain `UNKNOWN`.

`ROLLOUT_MISSING` is reserved for cases where absence can actually be established in the local filesystem namespace. A known temporary child that was never persisted is classified separately as `NEVER_PERSISTED_TEMP_CHILD`; lack of a thread row by itself is not evidence that a rollout was deleted. Likewise, `thread not found` or `os error 2` with a surviving rollout is not automatically data loss.

The upstream archive/resume failure itself remains a Codex issue. Rescue only reports the persisted evidence and never mutates Codex state as part of this diagnostic.

# Security

The simulator is offline: it contains no network client or subprocess execution. Spawned workers run only trial tasks and the parent process alone writes governed artifacts. NPZ checkpoints are loaded with pickle disabled and archive/member/metadata limits. Experiment IDs are restricted and resolved beneath the artifact root. Atomic temporary-file replacement is used for checkpoints and JSON evidence.

The approval JSON is a local authorization record, not a signature. The application is not an OS sandbox; run it using a dedicated account or VM if operating-system isolation is required. Do not run untrusted modified simulator source. Windows junction/reparse-point enforcement remains an operating-system deployment responsibility; keep the installation and artifact root owner-writable only.

The audit namespace is deterministic from the master seed and therefore lifecycle-held, not confidential. The current release path also relies on operator verification that the planned generation count is complete. Use trusted local storage; stale audit-lock recovery and stronger multi-file transaction/approval controls remain explicit limitations.

Report suspected artifact tampering by retaining the complete experiment directory and comparing its SHA-256 manifest before further execution.

v36-specific checkpoint, approval, audit, archive-export, and release boundaries are documented in [docs/V36_SECURITY.md](docs/V36_SECURITY.md). The scoped v36 approval is local and unsigned; it cannot override a failed terminal comparison.

v37-specific robustness, committed-audit-seed, specialist-bank, and three-way comparison boundaries are documented in [docs/V37_SECURITY.md](docs/V37_SECURITY.md).

The Codex improvement controller adds a local agentic surface. Codex is constrained to a candidate worktree with workspace-write sandboxing, noninteractive approval rejection, a retained and expiring parent human authorization, delegated development-only fixture authority, a two-file Git and raw-filesystem allowlist, forbidden-code scanning, full tests, trusted scoring, and branch-only retention. Codex receives a minimal environment and secret values are redacted from retained streams. Pre/post main and production-artifact inventories prove the non-modification result, and a recursive SHA-256 manifest seals each completed evidence bundle. These controls are defense in depth, not an OS sandbox: the Windows elevated workspace backend can execute processes, and application-level scanning cannot replace a disposable low-privilege VM when stronger containment is required. The Codex API is the explicit network exception; candidate simulator code is not authorized for network access. The controller never receives production release authority or records Codex credentials intentionally.

The eight-hour launcher requires a clean Git worktree, captures dependency and input hashes, disables Ollama, uses zero automatic retries, and scopes its kill switch to one experiment. These controls improve provenance but do not create an OS sandbox. Do not place credentials in runner environment overrides or evidence; use a dedicated low-privilege account or VM for stronger isolation.

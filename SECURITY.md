# Security

The simulator is offline: it contains no network client or subprocess execution. Spawned workers run only trial tasks and the parent process alone writes governed artifacts. NPZ checkpoints are loaded with pickle disabled and archive/member/metadata limits. Experiment IDs are restricted and resolved beneath the artifact root. Atomic temporary-file replacement is used for checkpoints and JSON evidence.

The approval JSON is a local authorization record, not a signature. The application is not an OS sandbox; run it using a dedicated account or VM if operating-system isolation is required. Do not run untrusted modified simulator source. Windows junction/reparse-point enforcement remains an operating-system deployment responsibility; keep the installation and artifact root owner-writable only.

The audit namespace is deterministic from the master seed and therefore lifecycle-held, not confidential. The current release path also relies on operator verification that the planned generation count is complete. Use trusted local storage; stale audit-lock recovery and stronger multi-file transaction/approval controls remain explicit limitations.

Report suspected artifact tampering by retaining the complete experiment directory and comparing its SHA-256 manifest before further execution.

v36-specific checkpoint, approval, audit, archive-export, and release boundaries are documented in [docs/V36_SECURITY.md](docs/V36_SECURITY.md). The scoped v36 approval is local and unsigned; it cannot override a failed terminal comparison.

v37-specific robustness, committed-audit-seed, specialist-bank, and three-way comparison boundaries are documented in [docs/V37_SECURITY.md](docs/V37_SECURITY.md).

The eight-hour launcher requires a clean Git worktree, captures dependency and input hashes, disables Ollama, uses zero automatic retries, and scopes its kill switch to one experiment. These controls improve provenance but do not create an OS sandbox. Do not place credentials in runner environment overrides or evidence; use a dedicated low-privilege account or VM for stronger isolation.

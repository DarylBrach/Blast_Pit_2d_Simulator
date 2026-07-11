# v37 Security Boundary

v37 loads only numeric NPZ artifacts through the hardened v36/v35 loaders with pickle disabled. Source checkpoint and implementation hashes are part of the lineage fingerprint and scoped approval. Audit seeds, checkpoints, policies, and approval are hash-bound in evidence.

The simulator is offline but is not an operating-system sandbox. It inherits the invoking user's filesystem authority. Historical v35/v36 artifacts are read-only baselines and are not mutated by v37.

Release is not authorized for this experiment. Future production hardening still requires broader Windows reparse-point, stale-lock/PID-reuse, interruption, and cross-platform soak qualification.

The eight-hour launcher improves containment by requiring clean versioned source, disabling networked Ollama classification, prohibiting automatic retry, using an experiment-scoped stop file, and recording source/dependency hashes. It still inherits the operator's filesystem and process authority. Run under a dedicated low-privilege account or VM when damage containment matters.

Approval is local unsigned JSON and must exactly bind `robustness-v37-8h-001`, the source/checkpoint, audit commitment, implementation fingerprint, total generation ceiling, and authorized actions. Training authorization is not release authorization. A stale stop file blocks startup; operators must review and remove it explicitly. Evidence can disclose paths, host metadata, and dependency versions, so protect it appropriately and never pass secrets through captured environment overrides.

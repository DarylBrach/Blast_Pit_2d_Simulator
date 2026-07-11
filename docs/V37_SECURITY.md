# v37 Security Boundary

v37 loads only numeric NPZ artifacts through the hardened v36/v35 loaders with pickle disabled. Source checkpoint and implementation hashes are part of the lineage fingerprint and scoped approval. Audit seeds, checkpoints, policies, and approval are hash-bound in evidence.

The simulator is offline but is not an operating-system sandbox. It inherits the invoking user's filesystem authority. Historical v35/v36 artifacts are read-only baselines and are not mutated by v37.

Release is not authorized for this experiment. Future production hardening still requires broader Windows reparse-point, stale-lock/PID-reuse, interruption, and cross-platform soak qualification.

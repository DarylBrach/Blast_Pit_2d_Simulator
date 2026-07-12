# Architecture

The v35 launcher contains six logical layers: immutable scientific/execution configuration; brain and mutation policy; deterministic world simulation; fitness and suite aggregation; evolution orchestration; and checkpoint/evidence persistence. Independent trials may execute in spawned processes. Workers return validated summaries; the parent restores canonical order and is the only artifact writer.

The Python engine is the semantic reference. It senses every living creature from the same pre-action spatial snapshot, performs batched or scalar inference, then applies actions in creature-ID order. Resource contention is deterministic. Fire is static and food/water indexes are incrementally maintained; only the moving-creature index rebuilds each frame. Engine and inference choices are fingerprinted so numerically distinct checkpoints cannot be mixed.

The next performance boundary, if profiling justifies it, is a structure-of-arrays full-frame engine. It must reproduce reference ordering on golden fixtures or declare a new scientific engine contract. A scalar Numba distance function alone is not represented as full-engine acceleration.

Numba/LLVM is lazy-loaded only when `--engine numba` is explicitly selected. The Python reference engine does not import or initialize the optional compiled runtime.

Operator recovery is checkpoint-led: `status` exposes a bounded metadata subset, `train` rejects occupied governed artifacts, and `continue` advances from the last atomic generation commit. Full `inspect` remains an evidence/debug surface and may emit a large embedded generation record.

## Improvement harness v2

Controller v2.2 is a three-plane candidate-development control system. Tool-less model roles return only schema-valid proposals. The trusted Windows controller applies allowlisted patches and manages the recoverable ACL lease. Candidate-controlled compile, tests, training, and trusted scoring execute only in the authorization-bound Linux Docker image. Controller, worktree, and supervisor evidence roots remain disjoint from the protected repository.

Controller v2.1 wraps each candidate worktree and disposable outputs in an ACL lease. Under a kernel controller lock, it snapshots exact SDDL, derives the restricted SID by exact rule-multiset comparison, persists `APPLYING`, installs only child inheritance-only `DELETE`, and runs the expanded canary. A persistent WAL and a sibling, hash-pinned copy of the exact authorization-bound helper support startup and emergency recovery even after checkout upgrades. The controller empties the disposable lease, restores and verifies the exact SDDL, then performs the production guard, seal, and publish in that order. Recovery has a separate manifest/decision/hash-chain ledger and a latest `RECOVERY_REQUIRED` hazard pointer.

Launcher Recover exposes only this recovery plane. It holds the same kernel lock and validates fixed paths/helper hashes, but enters WAL recovery and returns without a clean-check or candidate execution. Status/Verify are separate read-only evidence planes.

The container receives one read-only bind of the disposable workspace. Its only writable filesystems are bounded 256 MiB `/tmp` and `/output` tmpfs mounts. A trusted stdout exporter serializes training output as bounded safe relative paths, SHA-256 hashes, and base64; the host validates the complete export before materializing files. Image identity is fixed to `sha256:ebecafb90288df12553cb8b66e0bc2a3ce325513a19f65e40e5ce9e526db0698` and `candidate_image_attestation_v1.json` binds the hash-locked recipe. Windows audit-hook controls are supplemental only.

Container lifecycle intent is fsynced before Docker create. Normal, startup, emergency, and Recover paths remove governed containers and verify absence before restoring ACL leases. Unresolved container or ACL recovery independently blocks readiness and publication.

The architecture produces local candidate commits and sealed human-review evidence only. It has no production-training, merge, push, audit, promotion, export, or release path.

# Artifact Schema

- `evolution_state_v35.npz`: population, champion, development HOF, configuration, provenance, and last committed generation.
- `validation_hof_v35.npz`: portable development-confirmation Hall of Fame checkpoint; filename retained for tool continuity.
- `generations_v35.jsonl`: canonical hash-chained generation evidence.
- `sealed_audit_v35.json`: terminal workflow-holdout trials and aggregate.
- `approval_bound_v35.json`: copied approval and digest.
- `effective_config_v35.json`: scientific and execution configuration.
- `seed_suites_v35.json`: deterministic namespaces.
- `challenge_registry_v35.json`: challenge generator policy.
- `manifest_v35.json`: SHA-256 release inventory and cross-artifact identity.

All v35 metadata carries application/schema identity. NPZ loading forbids pickle and validates allowed members, size, shape, dtype, and finite brain values.

The checkpoint `config.generations` records the current run-segment length. `planned_generation_count` preserves the original fresh-run target across continuation; legacy checkpoints acquire it from their original `config.generations` on the next commit. `generations_v35.jsonl` and checkpoint `generation` remain the authoritative completed-history evidence.

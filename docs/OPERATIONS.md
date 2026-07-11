# Operations

All commands run from the package root. Use `run_blast_pit.bat` on Windows.

## Train

Use the README command only for a new experiment ID. `train` is fresh-only and fails closed if any governed state, Hall of Fame, generation log, or audit artifact already exists. Do not delete or overwrite retained production evidence to force a fresh run.

## Status and recovery

```bat
run_blast_pit.bat status --checkpoint artifacts\v35\v35-production-001\evolution_state_v35.npz
```

`status` reports the last committed generation, durable workflow state, planned/completed/remaining counts, seed, and execution identity without dumping the embedded generation record. Generation numbers are zero-based: generation 0 means one generation completed. For the retained `v35-production-001` checkpoint at generation 0, completing the original target of 50 requires `--additional-generations 49`.

## Continue

```bat
run_blast_pit.bat continue --experiment-id v35-production-001 --resume artifacts\v35\v35-production-001\evolution_state_v35.npz --additional-generations 20 --seed 20260711 --workers 8 --engine python --inference batch
```

`--additional-generations` is an increment, not a final target. Seed, engine, and inference backend must match the checkpoint; worker count may change. A worker failure before commit leaves the last checkpoint authoritative. Exit 3 is a validation/execution error; Ctrl-C exits 5 and retains the last committed generation.

## Inspect and visualize

```bat
run_blast_pit.bat inspect --checkpoint artifacts\v35\v35-production-001\evolution_state_v35.npz
run_blast_pit.bat visualize --checkpoint artifacts\v35\v35-production-001\validation_hof_v35.npz --seed 20260711
```

Controls: Esc quit; Space pause; period single-step; brackets speed; R deterministic restart; H sensor HUD.

## Audit and release

```bat
run_blast_pit.bat audit --experiment-id v35-production-001 --resume artifacts\v35\v35-production-001\evolution_state_v35.npz --seed 20260711 --workers 8 --engine python --inference batch
```

Audit is one-shot for a provenance identity and idempotent only when that identity is unchanged. If interruption occurs after the release checkpoint but before manifest publication, rerun the identical audit command; v35 deterministically rebuilds the missing manifest.

Exit codes: 0 success, 3 validation/provenance error, 5 interrupted with the last committed generation resumable.

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

## Improvement controller v2

From the repository root, use the Windows batch wrapper:

```powershell
.\run_codex_improvement_monitor.bat -Mode DryRun
.\run_codex_improvement_monitor.bat -Mode Recover
.\run_codex_improvement_monitor.bat -Mode Run -Cycles 1
.\run_codex_improvement_monitor.bat -Mode Status
.\run_codex_improvement_monitor.bat -Mode Review -Json
.\run_codex_improvement_monitor.bat -Mode Verify -RunId <run-id>
.\run_codex_improvement_monitor.bat -Mode Stop
.\run_codex_improvement_monitor.bat -Mode InspectTerminal -RunId <run-id>
```

Run uses a 28,200-second controller budget and 28,800-second supervisor ceiling. Increase `-Cycles` only after reviewing prior evidence; values 1–10 are cumulative attempts, not version numbers or guaranteed accepted improvements. InspectTerminal verifies terminal evidence only and never resumes partial work.

Controller v2.1 holds a kernel controller lock across startup recovery and execution. On startup it replays any incomplete ACL WAL and requires exact-SDDL restoration before permitting new candidate work. Do not manually remove a lease root, alter its ACL, edit its WAL, or confuse the kernel lock with the scoped stop file. A killed candidate run is not resumed; ACL recovery restores host state, after which a fresh governed run is required.

Recover acquires the same kernel lock, validates fixed paths and the per-lease archived helper hash, and strictly replays persisted ACL recovery before returning. It intentionally bypasses the normal clean-check because it cannot run a candidate or change source. It cannot continue a partial run. When a lease is present it creates a separate recovery decision/manifest, appends the recovery hash-chain ledger, updates `acl_recovery_latest.json`, and then removes the recovered disposable workspace. Status/Review/Verify surface an unresolved `RECOVERY_REQUIRED` pointer independently of the latest candidate run.

Historical v2.1 used a Windows audit guard and raw-versus-guarded canary. That mechanism is defense in depth only under v2.2 and is not the candidate hard boundary.

Ten cycles means up to ten attempts before the deadline. `10/10` means ten full-credit rubric dimensions totaling 100/100 and only readiness for human review. Final v2.2 totals and a successful clean-tree supported DryRun remain pending. First live run `20260711T223022Z-1128b831` is an unanchored failed diagnostic run, not an operational success record.

## Controller v2.2 Docker operation

The v2.1 audit-guard/count statements above are historical. Before Run/DryRun, Docker host identity, `candidate_image_attestation_v1.json`, the hash-locked recipe, and image `sha256:ebecafb90288df12553cb8b66e0bc2a3ce325513a19f65e40e5ce9e526db0698` must match authorization. Builds are reviewed maintenance; runs use pull-never. Compile/tests/train/trusted score are containerized with a read-only workspace, bounded 256 MiB `/tmp` and `/output`, and trusted stdout export only. Recover removes/verifies containers first, then restores ACL leases. Final v2.2 totals and successful DryRun remain pending.

Operator exits: `0` verified/review-ready (or successful DryRun), `1` missing or ambiguous selection, `2` blocked/incomplete/controller failure, `3` tampered or inconsistent evidence, and `130` interrupted controller execution. Human review pending never authorizes push, merge, training, audit, promotion, export, or release.

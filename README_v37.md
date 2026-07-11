# Blast_Pit v37 - Robustness QD-PPO

BLUF: v37 is a new robustness-focused lineage bootstrapped from the immutable v36 generation-20 archive. It does not continue v36 in place. It increases challenge exposure and reward contribution, applies terminal early-extinction penalties, blends mean and CVaR episode objectives, seeds from evaluated challenge specialists, and gives the critic five explicit lineage-context features while preserving the actor ABI.

## Activated DOS venv commands

```bat
python tmp_2d_simulator_v37.py status --checkpoint artifacts\v37\robustness-v37-002\evolution_state_v37.npz

python tmp_2d_simulator_v37.py audit --experiment-id robustness-v37-002 --checkpoint artifacts\v37\robustness-v37-002\evolution_state_v37.npz --v36-checkpoint artifacts\v36\qdppo-evaluation-001\evolution_state_v36.npz --v35-checkpoint artifacts\v35\v35-production-001\validation_hof_v35.npz --audit-seed-file audit_seeds_v37_002_committed.txt --audit-trials 64 --approval-record approval_v37_002.json
```

The initial `robustness-v37-001` exploratory run exposed trajectory/checkpoint defects and remains retained as failed evidence. The corrected `robustness-v37-002` experiment completed one planned generation with fresh approval and unseen seeds. Its 64-seed balanced audit also failed, so v37 is retained for failure analysis and is not released.

See [docs/V37_ARCHITECTURE.md](docs/V37_ARCHITECTURE.md), [docs/V37_ROBUSTNESS_OBJECTIVE.md](docs/V37_ROBUSTNESS_OBJECTIVE.md), [docs/V37_EVIDENCE.md](docs/V37_EVIDENCE.md), [docs/V37_SECURITY.md](docs/V37_SECURITY.md), [docs/V37_TESTING.md](docs/V37_TESTING.md), and [docs/V37_FINAL_QA.md](docs/V37_FINAL_QA.md).

## Governed eight-hour iteration

The operator entrypoint is `run_v37_8h.bat`, which invokes `run_v37_8h.ps1` with a process-scoped execution-policy bypass for locked-down Windows hosts; the complete procedure is [docs/V37_OPERATIONS.md](docs/V37_OPERATIONS.md). It uses experiment `robustness-v37-8h-001`, a 28,200-second simulator budget, a 300-second generation-boundary grace window, and a 28,800-second supervisor timeout. It supports dry-run and validated checkpoint resume while preserving the approved total generation ceiling.

The scoped `approval_v37_8h_001.json` and fresh 64-seed `audit_seeds_v37_8h_001_committed.txt` record the human-owner authorization from the 2026-07-11 Codex session. The launcher and simulator fail closed if either input or the frozen configuration drifts. Authorization permits bounded training; it does not guarantee improvement, authorize release, or waive terminal comparison gates.

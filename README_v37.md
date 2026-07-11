# Blast_Pit v37 - Robustness QD-PPO

BLUF: v37 is a new robustness-focused lineage bootstrapped from the immutable v36 generation-20 archive. It does not continue v36 in place. It increases challenge exposure and reward contribution, applies terminal early-extinction penalties, blends mean and CVaR episode objectives, seeds from evaluated challenge specialists, and gives the critic five explicit lineage-context features while preserving the actor ABI.

## Activated DOS venv commands

```bat
python tmp_2d_simulator_v37.py status --checkpoint artifacts\v37\robustness-v37-002\evolution_state_v37.npz

python tmp_2d_simulator_v37.py audit --experiment-id robustness-v37-002 --checkpoint artifacts\v37\robustness-v37-002\evolution_state_v37.npz --v36-checkpoint artifacts\v36\qdppo-evaluation-001\evolution_state_v36.npz --v35-checkpoint artifacts\v35\v35-production-001\validation_hof_v35.npz --audit-seed-file audit_seeds_v37_002_committed.txt --audit-trials 64 --approval-record approval_v37_002.json
```

The initial `robustness-v37-001` exploratory run exposed trajectory/checkpoint defects and remains retained as failed evidence. The corrected `robustness-v37-002` experiment completed one planned generation with fresh approval and unseen seeds. Its 64-seed balanced audit also failed, so v37 is retained for failure analysis and is not released.

See [docs/V37_ARCHITECTURE.md](docs/V37_ARCHITECTURE.md), [docs/V37_ROBUSTNESS_OBJECTIVE.md](docs/V37_ROBUSTNESS_OBJECTIVE.md), [docs/V37_EVIDENCE.md](docs/V37_EVIDENCE.md), [docs/V37_SECURITY.md](docs/V37_SECURITY.md), [docs/V37_TESTING.md](docs/V37_TESTING.md), and [docs/V37_FINAL_QA.md](docs/V37_FINAL_QA.md).

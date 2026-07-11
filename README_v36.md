# Blast_Pit v36 - Governed QD-PPO

BLUF: v36 now supports hardened checkpoint loading, exact-population continuation, concise status, full inspection, JSONL recovery, Hall-of-Fame and archive exports, accessible archive visualization, independent terminal comparison, scoped human approval, and a fail-closed release workflow.

The authoritative retained experiment is `qdppo-evaluation-001`. It reached generation 19 with 11/25 archive cells before lifecycle implementation and was then continued exactly to generation 20 with all 11 cells preserved. Its current Hall of Fame is candidate 201, policy `ee521f...`, first selected at generation 12. Generation 12 itself had 10 cells; 11 cells first appeared later. The continuation evidence is retained with the experiment.

## DOS/activated-venv commands

```bat
python tmp_2d_simulator_v36.py status --checkpoint artifacts\v36\qdppo-evaluation-001\evolution_state_v36.npz

python tmp_2d_simulator_v36.py continue --experiment-id qdppo-evaluation-001 --resume artifacts\v36\qdppo-evaluation-001\evolution_state_v36.npz --additional-generations 1 --seed 20260711 --approval-record approval_v36.json

python tmp_2d_simulator_v36.py export-hof --checkpoint artifacts\v36\qdppo-evaluation-001\evolution_state_v36.npz --output artifacts\v36\qdppo-evaluation-001\validation_hof_v36.npz

python tmp_2d_simulator_v36.py export-archive --checkpoint artifacts\v36\qdppo-evaluation-001\evolution_state_v36.npz --output artifacts\v36\qdppo-evaluation-001\archive_elites_v36

python tmp_2d_simulator_v36.py visualize-archive --checkpoint artifacts\v36\qdppo-evaluation-001\evolution_state_v36.npz --output artifacts\v36\qdppo-evaluation-001\archive_v36.svg
```

`train` is fresh-only and is not authorized by the current approval. `continue` reconstructs the deterministic post-commit emitter population, preserving archive parents, candidate IDs, optimizer state, seed namespaces, and lineage.

## Evidence and release boundary

The v36 approval is a scoped local human authorization, not a cryptographic signature. Terminal audit is a separate command and never trains either policy. Release requires approval, terminal evidence, and v36 meeting or exceeding the v35 median, minimum, and early-extinction baselines. The current comparison failed that gate, so v36 is not released.

See [docs/V36_OPERATIONS.md](docs/V36_OPERATIONS.md), [docs/V36_ARCHITECTURE.md](docs/V36_ARCHITECTURE.md), [docs/V36_EVIDENCE.md](docs/V36_EVIDENCE.md), [docs/V36_SECURITY.md](docs/V36_SECURITY.md), and [docs/V36_FINAL_QA.md](docs/V36_FINAL_QA.md).

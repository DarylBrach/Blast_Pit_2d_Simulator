# v37 Testing

Focused tests cover robustness bounds, CVaR weighting and small samples, the 64-seed commitment, actor-preserving critic migration, critic shape/context bounds, actual challenge profiles, deterministic specialist bootstrap, approval scope, CLI parsing, and positive-delta preservation.

Historical v37 evidence recorded 13 focused tests and 39 repository tests. The eight-hour workflow update expands this with simulator continuation/runtime tests and focused supervisor security/evidence tests; current final counts are recorded in `docs/V37_FINAL_QA.md`.

Run:

```bat
python -m pytest -q test_tmp_2d_simulator_v37.py
python -m pytest -q
```

The current experiment is a controlled one-generation evaluation, not proof of convergence or superiority.

Eight-hour workflow acceptance additionally requires:

- launcher dry-run command routing, clean/dirty Git behavior, missing/wrong approval rejection, stale scoped-stop rejection, and fresh/resume selection;
- fake-clock tests for the 28,200-second budget and 300-second commit grace inside the 28,800-second supervisor ceiling;
- kill, timeout, and interruption tests proving no orphan process and no partial-generation commit;
- resume parity with uninterrupted execution plus fail-closed source, configuration, seed, approval, checkpoint, and JSONL drift tests;
- atomically visible runner `RUNNING`/heartbeat/terminal state and complete hash/environment evidence with secret redaction;
- status correctness for completed, remaining, next action, `BUDGET_EXHAUSTED`, `TRAINING_COMPLETE`, and audit eligibility;
- a shortened integration soak using the same launcher path, followed by a full eight-hour operational qualification.

Documentation commands must be smoke-tested from PowerShell and from a different current directory. Passing mechanical tests does not establish empirical improvement.

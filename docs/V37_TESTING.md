# v37 Testing

Focused tests cover robustness bounds, CVaR weighting and small samples, the 64-seed commitment, actor-preserving critic migration, critic shape/context bounds, actual challenge profiles, deterministic specialist bootstrap, approval scope, CLI parsing, and positive-delta preservation.

Final evidence: 13 focused v37 tests passed; the full repository suite passed 39 tests.

Run:

```bat
python -m pytest -q test_tmp_2d_simulator_v37.py
python -m pytest -q
```

The current experiment is a controlled one-generation evaluation, not proof of convergence or superiority.

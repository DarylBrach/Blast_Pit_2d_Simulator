# v36 Testing

Run:

```bat
python -m py_compile tmp_2d_simulator_v35.py tmp_2d_simulator_v36.py
python -m unittest -v test_tmp_2d_simulator_v36.py
```

The 17 v36 module tests cover PPO/QD mathematics, policy/optimizer integrity, numeric checkpoints, hardened round-trip loading, status, checkpoint-ahead and partial-terminal repair, HoF export, SVG visualization, deterministic emitter reconstruction, CLI parsing, and the retained production checkpoint. The full pytest suite passes 26 tests. A copied production checkpoint was rehearsed before the authoritative population was continued from generation 19 to 20. The final state has a consistent 21-record chain, next candidate ID 337, 11 retained cells, and HoF source generation 12.

Release qualification still requires repeated cross-platform interruption, stale-lock, malformed-ZIP, reparse-point, and long-soak testing. Mechanical success is not an empirical superiority claim.

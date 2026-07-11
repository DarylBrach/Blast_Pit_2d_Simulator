# Blast_Pit Creature Simulator v35

BLUF: v35 is a deterministic, governed evolutionary simulator for Windows/Python 3.11. It corrects lineage and late-birth fitness, prevents trial-count changes from silently reweighting standard versus challenge suites, maintains static resource indexes incrementally, preserves parent-only evidence writes, and makes interrupted release-manifest creation recoverable.

## Install at the requested location

```bat
cd /d E:\Code\Python\VirtualEnvironments\Blast_Pit\2d_Simulator
py -3.11 -m venv .venv
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Smoke test

```bat
run_tests.bat
```

Verify optional Numba in the same interpreter used to launch the simulator:

```bat
python -c "import sys,numba; print(sys.executable, numba.__version__)"
```

Installing Numba does not accelerate `--engine python`. Use `--engine numba` only after parity testing and benchmarking, and never change engine or inference backend while continuing an experiment.

## Train

```bat
run_blast_pit.bat train --experiment-id v35-production-001 --generations 50 --trials 5 --challenge-trials 2 --validation-trials 7 --audit-trials 11 --max-frames 6000 --seed 20260711 --workers 8 --engine python --inference batch
```

Continue, inspect, visualize, and audit examples are in [docs/OPERATIONS.md](docs/OPERATIONS.md). Audit is explicit and is never run by training. The repeated fixed-seed suite is development confirmation because it selects the Hall of Fame; it is not represented as an untouched validation set. Audit seeds are workflow holdouts, not secrets.

`train` is fresh-only and refuses retained governed artifacts. Use `status` and then `continue` for a committed partial run; `--additional-generations` is the number to add beyond the last committed generation.

## Important compatibility rule

v34 checkpoints cannot be resumed by v35. The fitness, metric, engine, and evidence contracts changed. Finish existing v34 experiments with v34 or begin a new v35 experiment. See [docs/MIGRATION_V34_TO_V35.md](docs/MIGRATION_V34_TO_V35.md).

This local simulator performs no network or subprocess operations. It is not an OS sandbox and runs with the invoking user's filesystem privileges.

The governed QD-PPO v36 lifecycle and retained experiment are documented separately in [README_v36.md](README_v36.md). v36 has not replaced or been released over v35; its current identical-seed comparison did not clear the v35 release baseline.

The robustness-focused v37 experiment is documented in [README_v37.md](README_v37.md). It is a new v36-bootstrap lineage and also failed its empirical release gate.

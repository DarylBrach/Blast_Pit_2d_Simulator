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

The governed Codex improvement controller is documented in [docs/CODEX_IMPROVEMENT_LOOP.md](docs/CODEX_IMPROVEMENT_LOOP.md). It proposes and evaluates changes only in isolated candidate worktrees under an expiring, hash-bound human authorization; it retains sealed evidence and never modifies, merges, pushes, or releases `main` automatically. Use `run_codex_improvement_monitor.bat`, not the PowerShell file directly, on execution-policy-restricted Windows systems.

The supported controller v2.2 harness and read-only evidence consumer are documented in [docs/CODEX_IMPROVEMENT_LOOP.md](docs/CODEX_IMPROVEMENT_LOOP.md) and [docs/CODEX_IMPROVEMENT_OPERATOR_V2.md](docs/CODEX_IMPROVEMENT_OPERATOR_V2.md). `run_codex_improvement_monitor.bat` supports Run, DryRun, Recover, Status, Review, Verify, Stop, and terminal-only InspectTerminal modes. Tool-less roles propose changes; the controller owns the Windows patch/ACL boundary; and every candidate-controlled compile, test, training, and trusted-scoring command runs in authorization-bound Linux Docker image `sha256:ebecafb90288df12553cb8b66e0bc2a3ce325513a19f65e40e5ce9e526db0698`. The disposable workspace bind is read-only. Writable `/tmp` and `/output` are separate 256 MiB tmpfs mounts, and training results cross only through a trusted bounded stdout exporter with safe relative paths, per-file SHA-256, and base64 payloads. Recover handles governed containers first and ACL leases second. Ten cycles means up to ten attempts; `10/10` means 100/100 and readiness for human review only.

The first v2 live run, `20260711T223022Z-1128b831`, failed closed before the sandbox canary because the CLI performed an atomic-delete operation that the earlier ACL policy denied. Production remained unchanged. Its sealed files were never anchored in the local ledger, so the run is retained as unanchored diagnostic evidence, not successful qualification. Final v2.2 suite totals, live container qualification, and a successful clean-tree supported DryRun remain pending validation.

The corrected ten-cycle v1.1 run completed with sealed evidence and no production changes, but final QA found that cycle 10 self-classified an algorithmic Hall-of-Fame change as `process`. That candidate is blocked; `de3be87` is the last pre-failure v1.1 accepted ancestor, has not been revalidated under v1.2, and remains pending human review. Controller v1.2 treats every simulator-source change as algorithmic and routes normal disposable output to evidence-sealed cycle scratch space. The original v1.1 authorization and separate v1.2 amendment remain preserved as historical evidence; the supported launcher now selects controller v2. No candidate is merged, pushed, audited, released, or approved for production.

The governed v37 eight-hour operator workflow is [docs/V37_OPERATIONS.md](docs/V37_OPERATIONS.md). Use `run_v37_8h.ps1 -DryRun` first. The launcher is deliberately approval-gated and will not reuse an older experiment's authorization.

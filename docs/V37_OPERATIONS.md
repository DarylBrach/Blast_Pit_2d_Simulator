# v37 Eight-Hour Operations

## BLUF

`run_v37_8h.ps1` is the governed entrypoint for `robustness-v37-8h-001`. It requires a clean Git worktree, an exact experiment-scoped human approval, and a committed audit-seed file. The simulator receives 28,200 seconds (7h50m) and reserves at least 300 seconds to avoid starting an unsafe final generation; the supervisor enforces an absolute 28,800-second (8h) ceiling. Retries and Ollama are disabled, and the child receives the runner's minimal governed environment.

The launcher ships with `approval_v37_8h_001.json` and `audit_seeds_v37_8h_001_committed.txt`, created from the human-owner authorization in the 2026-07-11 Codex session. The approval binds the frozen source, v36 checkpoint, seed commitment, 100-generation ceiling, 28,200-second graceful budget, and experiment identity. Existing v37 approvals cannot be reused.

## Preflight and dry run

Use the repository interpreter explicitly:

```powershell
Set-Location 'E:\Code\Python\VirtualEnvironments\Blast_Pit\2d_Simulator'
git status --short
& 'E:\Code\Python\VirtualEnvironments\Blast_Pit\Scripts\python.exe' -m pytest -q
.\run_v37_8h.bat -DryRun
```

The launcher rejects a dirty worktree, absent Git metadata, missing Python, stale scoped stop file, wrong approval identity, missing `train` authority, or missing seed commitment. A successful dry run records the Git commit and remote, Python version, `pip freeze`, input SHA-256 hashes, selected fresh/resume mode, and the effective runner command under `run_evidence\robustness-v37-8h-001`.

Review that evidence and the resolved command before execution. The approved `Generations` value is a total ceiling and must remain identical on resume.

## Execute and monitor

```powershell
.\run_v37_8h.bat
```

In another PowerShell window:

```powershell
Get-Content '.\run_evidence\robustness-v37-8h-001\latest\robustness-v37-8h-001_state.json'

& 'E:\Code\Python\VirtualEnvironments\Blast_Pit\Scripts\python.exe' `
  '.\tmp_2d_simulator_v37.py' status `
  --checkpoint '.\artifacts\v37\robustness-v37-8h-001\evolution_state_v37.npz'
```

Only committed generations are durable. `BUDGET_EXHAUSTED` means the last complete generation is retained and resumable; it is not audit-eligible. `TRAINING_COMPLETE` means the approved generation ceiling was reached and terminal audit may be separately considered.

## Stop and recover

Use the experiment-scoped switch instead of `Ctrl+C`:

```powershell
New-Item '.\.supervisor_stop.robustness-v37-8h-001' -ItemType File
```

After the runner records termination, review the latest state and checkpoint status. Remove the switch deliberately, then dry-run recovery:

```powershell
Remove-Item -LiteralPath '.\.supervisor_stop.robustness-v37-8h-001'
.\run_v37_8h.bat -DryRun
.\run_v37_8h.bat
```

When the checkpoint exists, the launcher supplies `train --resume`. Resume validates the same source, implementation, seed commitment, approval, configuration, and planned total generation ceiling. Never delete an occupied experiment directory or alter retained JSONL/checkpoint evidence to force restart.

## Audit and evidence seal

Do not audit `BUDGET_EXHAUSTED`, interrupted, killed, timed-out, or empirically incomplete training. Confirm `TRAINING_COMPLETE` and zero remaining generations first. Audit is a separate approved action and empirical failure cannot be overridden by human authorization.

Retain the complete simulator experiment directory and runner evidence directory. Generate a final recursive SHA-256 manifest only after all processes have exited; record the Git commit and `git status --short` beside it. Large checkpoints should be stored in access-controlled immutable storage while their manifests remain versioned.

## Exit interpretation

- `0`: supervised command succeeded; inspect simulator state before claiming completion.
- `1`: runner configuration, lock, or preflight failure.
- `2`: target failed, timed out, stalled, or was killed.
- `3`: simulator validation or execution rejection.
- `130`: operator interrupt; verify no child remains and prefer the scoped switch next time.

# Governed Codex Improvement Loop

## BLUF

`run_codex_improvement_monitor.bat` launches `CodexLightRunner_v3.py`, which supervises `CodexImprovementController_v1.py`. The controller gives Codex an isolated Git worktree, permits changes to only the v37 implementation and focused v37 tests, reruns repository validation, trains a disposable development fixture, scores its checkpoint with the trusted `main` evaluator, and retains an accepted candidate as a local branch commit.

It does not edit `main`, reuse terminal audit seeds, modify the completed `robustness-v37-8h-001` evidence, push branches, merge changes, run terminal audit, or release a policy.

## State and authority

The controller persists `BASELINE_EVALUATING`, `RUNNING`, per-cycle `WORKTREE_CREATING`, `CODEX_RUNNING`, `SECURITY_VALIDATING`, `TESTING`, `EVALUATING`, and terminal `ACCEPTED_CANDIDATE_BRANCH`, `REJECTED`, or `ERROR` states. The overall terminal state is `COMPLETE`.

The user's 2026-07-11 authorization permits disposable development evaluation. Each fixture receives an experiment-specific local approval with `development_fixture: true`, `train` authority only, and no audit, export, release, or production-promotion authority.

## Safety gates

- Base repository must be clean.
- Each cycle starts in a new `codex/improvement-*` Git worktree and branch.
- Codex runs noninteractively with `--sandbox workspace-write`, `approval_policy="never"`, structured output, ephemeral session storage, and ignored user configuration.
- Only `tmp_2d_simulator_v37.py` and `test_tmp_2d_simulator_v37.py` may change.
- Added subprocess, network, dynamic-code execution, shell, and deletion primitives are rejected.
- Diff size and symlink changes are bounded or rejected.
- Python compilation and the full repository test suite must pass.
- The candidate is trained with development-only seeds and a small deterministic fixture.
- The checkpoint is scored by the unchanged trusted evaluator from `main` on a separate deterministic development suite.
- Process/correctness changes must remain within non-regression limits. Algorithm changes must also improve CVaR or mean fitness by at least 0.005.
- Accepted changes are committed only to the candidate branch. Promotion to `main` remains human-reviewed.

These controls make the loop autonomous in proposing, testing, evaluating, and retaining candidates. They do not make it an operating-system sandbox or grant production authority.

## Dry run

```powershell
Set-Location 'E:\Code\Python\VirtualEnvironments\Blast_Pit\2d_Simulator'
.\run_codex_improvement_monitor.bat -DryRun
```

The dry run verifies repository state and produces a deterministic baseline development score, but does not invoke Codex or create a candidate worktree.

## Run and monitor

```powershell
.\run_codex_improvement_monitor.bat -Cycles 1
```

Runner live state:

```powershell
Get-Content '.\run_evidence\codex-improvement-controller\latest\codex-improvement-controller_state.json'
```

Controller state:

```powershell
Get-Content "$HOME\.codex_light_runner\improvements\Blast_Pit_2d_Simulator\latest.json"
```

Stop the supervised controller:

```powershell
New-Item '.\.supervisor_stop.codex-improvement-controller' -ItemType File
```

Remove a stale stop file only after reviewing the retained runner and controller evidence.

## Candidate review and promotion

The controller's `latest.json` records the final candidate commit and worktree. Review the patch, tests, deterministic score, risks, and Git branch. A human may then open a pull request or reject the branch. Any production experiment after a source change requires a new experiment ID, seed commitment, fingerprint, and approval; historical approval must never be rewritten.

## Limitations

- Development scores are deterministic screening evidence, not a terminal audit or proof of general superiority.
- Codex authentication is inherited from the installed CLI; credentials are not recorded in evidence.
- Worktrees are retained for auditability and require deliberate later cleanup.
- The controller does not push or merge candidate branches.
- A compromised operating-system account can exceed application-level controls; use a dedicated account or VM for stronger isolation.

# Governed Codex Improvement Loop

## BLUF

`run_codex_improvement_monitor.bat` launches `CodexLightRunner_v3.py`, which supervises `CodexImprovementController_v1.py`. The controller gives Codex an isolated Git worktree, permits changes to only the v37 implementation and focused v37 tests, reruns repository validation, trains a disposable development fixture, scores its checkpoint with the trusted `main` evaluator, and retains an accepted candidate as a local branch commit.

It does not edit `main`, reuse terminal audit seeds, modify the completed `robustness-v37-8h-001` evidence, push branches, merge changes, run terminal audit, or release a policy.

## State and authority

The controller persists `BASELINE_EVALUATING`, `RUNNING`, per-cycle `WORKTREE_CREATING`, `CODEX_RUNNING`, `SECURITY_VALIDATING`, `TESTING`, `EVALUATING`, and terminal `ACCEPTED_CANDIDATE_BRANCH`, `REJECTED`, or `ERROR` states. The overall terminal state is `COMPLETE`.

The retained `approval_codex_improvement_v1.json` records the user's 2026-07-11 authorization, expires on 2026-08-11, binds the controller, candidate driver, trusted scorer, development seeds, two-file allowlist, ten-cycle ceiling, and 28,800-second runtime ceiling, and denies automatic push, merge, audit, or release. Each fixture receives an experiment-specific `controller-development-delegation` with the parent authorization hash, `development_fixture: true`, a 600-second internal runtime budget, `train` authority only, and no audit, export, release, or production-promotion authority. The controller does not represent an automatically created child record as a new human approval.

## Safety gates

- Base repository must be clean.
- Each cycle starts in a new `codex/improvement-*` Git worktree and branch.
- Codex runs noninteractively with the locally supported `gpt-5.5` model, high reasoning effort, `--sandbox workspace-write`, the explicit Windows elevated sandbox backend, `approval_policy="never"`, structured output, ephemeral session storage, and ignored user configuration. Pinning the model and sandbox backend avoids inheriting incompatible cached desktop settings. JSONL events stream live into both controller evidence and CodexLightRunner output.
- Only `tmp_2d_simulator_v37.py` and `test_tmp_2d_simulator_v37.py` may change. An external pre-Codex filesystem manifest detects raw changes without trusting candidate Git metadata.
- Added subprocess, network, dynamic-code execution, shell, and deletion primitives are rejected.
- Diff size and symlink changes are bounded or rejected.
- Python compilation and the full repository test suite must pass.
- The candidate is trained with development-only seeds and a small deterministic fixture.
- The checkpoint is scored by the unchanged trusted evaluator from `main` on a separate deterministic development suite.
- Codex receives a minimal environment allowlist; retained event streams redact passed secret values and bearer credentials. The Codex API is the only authorized network exception, while candidate simulator code remains network-denied.
- Pre/post evidence records main HEAD, Git tree, worktree status, and SHA-256/size/mtime inventory for the retained production experiment. `production_modified` is derived from this comparison rather than asserted.
- Each completed controller bundle is sealed by `evidence_manifest.json`, which hashes every retained evidence file except the manifest itself to avoid self-reference.
- Process/correctness changes must remain within non-regression limits. Algorithm changes must also improve CVaR or mean fitness by at least 0.005.
- Accepted and rejected hypotheses, summaries, risks, decision-relevant score metrics, and gate failures from the six most recent cycles across completed and current runs are compacted into later prompts so the autonomous loop retains recent lessons and corrects prior regressions without exceeding Windows command-line limits. Ignored disposable files are included in the raw-filesystem gate and must be written outside the worktree or removed before the agent finishes.
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

The batch wrapper is the supported Windows entrypoint and uses a process-local PowerShell execution-policy bypass. Both CodexLightRunner and the parent authorization cap a controller invocation at eight hours. `-Cycles` may be 1 through 10; start with one cycle and review its evidence before increasing autonomy.

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

The controller's `latest.json` records the final candidate commit, worktree, authorization hash, and evidence-manifest hash. Review the patch, tests, deterministic score, risks, raw-filesystem gate, production guard, manifest, and Git branch. A human may then open a pull request or reject the branch. Any production experiment after a source change requires a new experiment ID, seed commitment, fingerprint, and approval; historical approval must never be rewritten.

## Operational validation: 2026-07-11

Controller v1.1 completed supervised run `20260711T171731Z` from clean main commit `0ad47fb`. It loaded six cross-run lessons, corrected a prior ignored-artifact rejection, passed the Git and raw-filesystem two-file gates, passed 83 candidate tests, and retained local candidate commit `47da614` without changing main or the completed production experiment. Trusted 32-seed screening improved CVaR from 0.269109 to 0.380316, mean from 0.424988 to 0.452221, standard mean from 0.494482 to 0.497590, and early extinction from 0.03125 to 0. The 34-file controller evidence manifest revalidated with SHA-256 `83ae131cdd8a333bacfb785d73fb5243ecb6b7c4481a31aff208b2661144fea4`.

This validates autonomous propose, edit, test, evaluate, learn, clean up, and retain behavior. It does not promote the candidate: the branch remains local, terminal audit was not run, and a source-changed production experiment still requires new human approval and lineage evidence.

## Limitations

- Development scores are deterministic screening evidence, not a terminal audit or proof of general superiority.
- Codex authentication is inherited from the installed CLI; credentials are not recorded in evidence.
- Worktrees are retained for auditability and require deliberate later cleanup.
- The controller does not push or merge candidate branches.
- A compromised operating-system account can exceed application-level controls; use a dedicated account or VM for stronger isolation.
- The retained human authorization is a local authorization record, not a cryptographic signature. Renew it deliberately after expiry or any bound source/seed/allowlist change.

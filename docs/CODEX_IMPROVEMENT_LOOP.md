# Governed Codex Improvement Loop

## BLUF

`run_codex_improvement_monitor.bat` launches `CodexLightRunner_v3.py`, which supervises `CodexImprovementController_v1.py`. The controller gives Codex an isolated Git worktree, permits changes to only the v37 implementation and focused v37 tests, reruns repository validation, trains a disposable development fixture, scores its checkpoint with the trusted `main` evaluator, and retains an accepted candidate as a local branch commit.

It does not edit `main`, reuse terminal audit seeds, modify the completed `robustness-v37-8h-001` evidence, push branches, merge changes, run terminal audit, or release a policy.

## State and authority

The controller persists `BASELINE_EVALUATING`, `RUNNING`, per-cycle `WORKTREE_CREATING`, `CODEX_RUNNING`, `SECURITY_VALIDATING`, `TESTING`, `EVALUATING`, and terminal `ACCEPTED_CANDIDATE_BRANCH`, `REJECTED`, or `ERROR` states. The overall terminal state is `COMPLETE`.

The retained `approval_codex_improvement_v1.json` is the immutable controller v1.1 authorization used by the ten-cycle run. Controller v1.2 uses the separate `approval_codex_improvement_v1_2.json` amendment, which records the prior authorization SHA-256, expires on 2026-08-11, and binds the v1.2 controller, candidate driver, trusted scorer, development seeds, two-file allowlist, ten-cycle ceiling, and 28,800-second runtime ceiling. Both deny automatic push, merge, audit, or release. Each fixture receives an experiment-specific `controller-development-delegation` with the active parent authorization hash, `development_fixture: true`, a 600-second internal runtime budget, `train` authority only, and no audit, export, release, or production-promotion authority. The controller does not represent an automatically created child record as a new human approval.

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
- Codex receives a minimal environment allowlist; retained event streams redact passed secret values and bearer credentials. `TEMP` and `TMP` are redirected to a per-cycle `codex_scratch` directory inside the sealed evidence bundle, and the prompt instructs the agent not to write to the user profile, Codex memories, system temporary directory, or other external paths. This routes cooperative temporary output into evidence but is not OS-level containment of explicit absolute-path writes. The Codex API is the only authorized network exception, while candidate simulator code remains network-denied.
- Pre/post evidence records main HEAD, Git tree, worktree status, and SHA-256/size/mtime inventory for the retained production experiment. `production_modified` is derived from this comparison rather than asserted.
- Each completed controller bundle is sealed by `evidence_manifest.json`, which hashes every retained evidence file except the manifest itself to avoid self-reference.
- Process/correctness changes must remain within non-regression limits. Algorithm changes must also improve CVaR or mean fitness by at least 0.005. Controller v1.2 fail-closes every change to `tmp_2d_simulator_v37.py` as effective category `algorithm`, regardless of names or the proposing agent's category. Test-only changes can retain a declared process/correctness category. Declared and effective categories are both retained as evidence.
- Accepted and rejected hypotheses, summaries, risks, decision-relevant score metrics, and gate failures from the six most recent cycles across completed and current runs are compacted into later prompts so the autonomous loop retains recent lessons and corrects prior regressions without exceeding Windows command-line limits. Ignored disposable files remain covered by the raw-worktree gate. Any necessary scratch files must stay in the controller-provided, evidence-sealed cycle scratch directory.
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

Controller v1.1 completed the corrected ten-cycle supervised run `20260711T183548Z` from clean controller-branch commit `c1762b2`. The runner returned `SUCCESS` after 4,257 seconds. The controller recorded six accepted and four rejected cycles, 206 evidence files, evidence-manifest SHA-256 `51b5d7d833ea4cf0e21d26562304159a604db7d7bb2d85e55c973b634e080924`, and `production_modified: false`. Independent verification rehashed the full manifest, reran the final branch's 89 tests, and confirmed unchanged protected HEAD, tree, worktree status, and all four production artifact identities.

Final QA invalidated cycle 10's controller acceptance. Commit `ff38a1b` changed Hall-of-Fame promotion behavior but declared category `process`; because v1.1 trusted that label, identical metrics bypassed the required algorithm improvement threshold. The retained evidence is valid and must not be rewritten, but `ff38a1b` is blocked from promotion. Commit `de3be87` is the last controller-accepted ancestor before that classification failure and remains candidate-only pending human review. Cycle 8 also created disposable self-evaluation files outside the sealed run under the Codex memory directory; those files are not trusted evaluation evidence.

Controller v1.2 closes the category-bypass finding by treating every simulator-source change as algorithmic. It mitigates, but does not claim OS-level closure of, external writes by redirecting normal temporary output into the sealed per-cycle scratch directory and explicitly forbidding other locations in the prompt. The original v1.1 authorization remains unchanged; the launcher now selects the versioned v1.2 amendment. This validates fail-closed monitoring and evidence retention, not unattended promotion: no candidate was merged, pushed, audited, released, or used for production training, and any source-changed production experiment still requires updated documentation, a new experiment ID, seed commitment, fingerprint, and human approval.

## Limitations

- Development scores are deterministic screening evidence, not a terminal audit or proof of general superiority.
- Codex authentication is inherited from the installed CLI; credentials are not recorded in evidence.
- Worktrees are retained for auditability and require deliberate later cleanup.
- The controller's diff classifier is intentionally conservative and may route a correctness fix through the stricter algorithm gate; a human may review a rejected candidate but must not rewrite retained run evidence.
- The controller does not push or merge candidate branches.
- A compromised operating-system account can exceed application-level controls; use a dedicated account or VM for stronger isolation.
- The elevated Windows Codex backend can still write an explicitly named absolute path outside `TEMP`/`TMP`; use a disposable account or VM when external-write containment is mandatory.
- The retained human authorization is a local authorization record, not a cryptographic signature. Renew it deliberately after expiry or any bound source/seed/allowlist change.

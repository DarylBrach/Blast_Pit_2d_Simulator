# Governed Codex Improvement Loop

## BLUF

`run_codex_improvement_monitor.bat` launches `CodexLightRunner_v3.py`, which supervises controller v2.2 in `CodexImprovementController_v2.py`. Every model role is tool-less and returns schema-validated JSON. The controller alone may apply a bounded patch through the Windows write boundary; every candidate-controlled compile, test, training, and trusted-scoring command runs in the authorization-bound Linux container. Seven specialist roles and independent final QA review each surviving candidate.

It does not edit the protected checkout, reuse terminal audit seeds, modify the completed `robustness-v37-8h-001` evidence, push branches, merge changes, run terminal audit, export, promote, or release a policy. A sealed 100/100 decision means ready for human review only.

## Historical v1 state and authority

The following v1 sections and commands are retained only to interpret historical evidence. They are not the current launcher contract; use the controller v2 operations section below.

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

## Historical v1 dry run

```powershell
Set-Location 'E:\Code\Python\VirtualEnvironments\Blast_Pit\2d_Simulator'
.\run_codex_improvement_monitor.bat -DryRun
```

The dry run verifies repository state and produces a deterministic baseline development score, but does not invoke Codex or create a candidate worktree.

## Historical v1 run and monitor

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

## Historical v1 candidate review

The controller's `latest.json` records the final candidate commit, worktree, authorization hash, and evidence-manifest hash. Review the patch, tests, deterministic score, risks, raw-filesystem gate, production guard, manifest, and Git branch. A human may then open a pull request or reject the branch. Any production experiment after a source change requires a new experiment ID, seed commitment, fingerprint, and approval; historical approval must never be rewritten.

## Operational validation: 2026-07-11

Controller v1.1 completed the corrected ten-cycle supervised run `20260711T183548Z` from clean controller-branch commit `c1762b2`. The runner returned `SUCCESS` after 4,257 seconds. The controller recorded six accepted and four rejected cycles, 206 evidence files, evidence-manifest SHA-256 `51b5d7d833ea4cf0e21d26562304159a604db7d7bb2d85e55c973b634e080924`, and `production_modified: false`. Independent verification rehashed the full manifest, reran the final branch's 89 tests, and confirmed unchanged protected HEAD, tree, worktree status, and all four production artifact identities.

Final QA invalidated cycle 10's controller acceptance. Commit `ff38a1b` changed Hall-of-Fame promotion behavior but declared category `process`; because v1.1 trusted that label, identical metrics bypassed the required algorithm improvement threshold. The retained evidence is valid and must not be rewritten, but `ff38a1b` is blocked from promotion. Commit `de3be87` is the last controller-accepted ancestor before that classification failure and remains candidate-only pending human review. Cycle 8 also created disposable self-evaluation files outside the sealed run under the Codex memory directory; those files are not trusted evaluation evidence.

Controller v1.2 closes the category-bypass finding by treating every simulator-source change as algorithmic. It mitigates, but does not claim OS-level closure of, external writes by redirecting normal temporary output into the sealed per-cycle scratch directory and explicitly forbidding other locations in the prompt. The original v1.1 authorization remains unchanged; the launcher selected the versioned v1.2 amendment for that historical validation. This validates fail-closed monitoring and evidence retention, not unattended promotion: no candidate was merged, pushed, audited, released, or used for production training, and any source-changed production experiment still requires updated documentation, a new experiment ID, seed commitment, fingerprint, and human approval.

The supported batch launcher then completed clean-tree v1.2 dry run `20260711T200515Z` from commit `6fe2eb3`. The controller loaded the shipped v1.2 amendment and its enforced v1.1 prior hash, reproduced the deterministic baseline, returned `DRY_RUN_COMPLETE`, proved `production_modified: false`, and sealed the controller bundle with manifest SHA-256 `96d1c12159614e56e6e0d753299205e3c78c3dcab53162b44511d56a0bbc2ba7`; CodexLightRunner returned `SUCCESS`.

## Historical v1 limitations

- Development scores are deterministic screening evidence, not a terminal audit or proof of general superiority.
- Codex authentication is inherited from the installed CLI; credentials are not recorded in evidence.
- Worktrees are retained for auditability and require deliberate later cleanup.
- The controller's diff classifier is intentionally conservative and may route a correctness fix through the stricter algorithm gate; a human may review a rejected candidate but must not rewrite retained run evidence.
- The controller does not push or merge candidate branches.
- A compromised operating-system account can exceed application-level controls; use a dedicated account or VM for stronger isolation.
- The elevated Windows Codex backend can still write an explicitly named absolute path outside `TEMP`/`TMP`; use a disposable account or VM when external-write containment is mandatory.
- The retained human authorization is a local authorization record, not a cryptographic signature. Renew it deliberately after expiry or any bound source/seed/allowlist change.

## Controller v2 operations

The supported Windows entrypoint is `run_codex_improvement_monitor.bat`. Controller v2 uses cumulative candidate ancestry, seven tool-less specialist roles, independent final QA, sandboxed validation/evaluation, and sealed operator decisions. The v1 history above remains immutable historical evidence.

```powershell
.\run_codex_improvement_monitor.bat -Mode DryRun
.\run_codex_improvement_monitor.bat -Mode Recover
.\run_codex_improvement_monitor.bat -Mode Run -Cycles 1
.\run_codex_improvement_monitor.bat -Mode Status
.\run_codex_improvement_monitor.bat -Mode Review
.\run_codex_improvement_monitor.bat -Mode Verify -RunId <run-id>
.\run_codex_improvement_monitor.bat -Mode Stop
.\run_codex_improvement_monitor.bat -Mode InspectTerminal -RunId <run-id>
```

Run and DryRun use a 28,200-second controller budget inside the supervisor's absolute 28,800-second limit. `-Cycles 10` means attempt up to ten cumulative cycles before the shared deadline. A cycle may be accepted, rejected, time out, or fail; it is not a simulator version increment and does not imply v37 through v47.

Builders and remediators are tool-less and return schema-validated, bounded unified patches; the controller applies an accepted patch inside the allowlisted sandbox. Seven specialist roles and final QA are also tool-less evidence reviewers. Candidate testing uses the sandbox, paired private Fold B screens cycle changes, and held-out Fold C supports final root adjudication. A 100/100 sealed decision means ready for human review only. It never authorizes merge, push, production training, terminal audit, export, promotion, or release.

### v2.2 containment and recovery

Each candidate cycle owns a disposable ACL lease root. The controller snapshots its exact SDDL, discovers the restricted SID by exact access-rule multiset difference, durably records `APPLYING`, and grants that SID only inheritance-only `DELETE` on descendants. The lease root itself remains non-deletable, and `WRITE_DAC` and `WRITE_OWNER` remain denied. A kernel controller lock prevents concurrent startup or recovery. The exact authorization-bound helper is copied to a non-candidate-writable, hash-named sibling before ACL mutation, so later source upgrades cannot strand the WAL. Exact SDDL restoration and verification must finish before the production guard, run seal, or publication. Every recovery attempt also receives its own decision, manifest, hash-chain ledger entry, and latest hazard pointer.

The Windows sandbox and audit guard are defense in depth for trusted host orchestration, not the candidate hard boundary. Every candidate-controlled command executes in immutable attested Linux image `sha256:ebecafb90288df12553cb8b66e0bc2a3ce325513a19f65e40e5ce9e526db0698`. `candidate_image_attestation_v1.json` records the image build inputs and package SBOM; the authorization separately hash-binds the attestation, exact runtime policy, canary, controller, and launch surfaces. Governed runs never build, pull, or substitute an image.

The container has no network, runs non-root with a read-only root filesystem, drops every capability, and receives exactly one host bind: the disposable workspace mounted read-only. Writable `/tmp` and `/output` are bounded 256 MiB tmpfs mounts. Training output leaves `/output` only through a trusted bounded stdout exporter; each safe relative path, size, SHA-256, and base64 payload is validated before host materialization. The full gate combines the trusted protected-harness suite with the containerized complete v37 candidate tests.

`-Cycles 10` means at most ten attempts under the shared deadline. `10/10` means ten rubric dimensions at 10 points each, or 100/100; it does not mean ten cycles or ten accepted improvements, and it grants human-review readiness only.

First live run `20260711T223022Z-1128b831` and pre-v3.1 DryRun `20260712T005807Z-709f67a4` remain historical evidence. Current local qualification is 241 passed/3 skipped in 54.51 seconds; governed-host live binding separately passes 1/1. Current supported DryRun is runner `20260712T014740Z-04461e70` / controller `20260712T014742Z-2a8b7152`.

`-Mode Recover` acquires the kernel controller lock, validates fixed paths and bound identities, removes and verifies absence of governed candidate containers first, then performs strict persisted ACL-lease recovery. It bypasses the normal clean-check solely because it cannot run candidates or change source. Container and ACL recovery attempts have separate sealed/ledgered decisions and latest hazard pointers. Recover does not resume a partial run; use Status or Verify for evidence disposition.

### Runner v3.1 seal

Supervisor and controller seals are separate. Runner v3.1 uses manifest v2, kernel locks, pre-allocation WAL recovery, and terminal and name-binding hash-chain ledgers. Each terminal row records `name_binding_hash`; `_terminal` binds the row by `ledger_hash` and is authoritative, while `_state` is advisory/live. Post-v3.1 supported DryRun runner `20260712T014740Z-04461e70` completed controller run `20260712T014742Z-2a8b7152` as `DRY_RUN_COMPLETE`; Recover and controller Verify returned 0, production remained unchanged, and active containers/leases were empty. Status/Review correctly returned 1 because DryRun leaves execution/review/promotion `NOT_RUN` and rubric 0/100. Runner success does not make the decision review-ready; earlier evidence above remains historical and exact.

InspectTerminal verifies an already terminal immutable run. It does not resume partial work. A killed, timed-out, or partial run must be retained and followed by a fresh recovery run. Status/Review/Verify are read-only and use the operator contract documented in [CODEX_IMPROVEMENT_OPERATOR_V2.md](CODEX_IMPROVEMENT_OPERATOR_V2.md).

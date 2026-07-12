# Improvement Operator v2

## BLUF

`improvement_operator.py` is a read-only inspection tool for completed v2.2 evidence bundles. It reports run disposition plus independent governed-container and ACL-recovery hazards. Publication requires verified container quiescence and exact-SDDL restoration. The operator cannot recover host state, start or resume the controller, modify evidence, approve promotion, run terminal audit, merge, push, or release anything.

The supported v2 launcher is `run_codex_improvement_monitor.bat`. It selects separate controller, worktree, and runner evidence roots beside the protected checkout.

## Evidence root

Pass the controller artifact root containing `latest.json` and run directories:

```text
<artifact-root>/
  latest.json
  <run-id>/
    operator_decision.json
    state.json
    transitions.jsonl
    production_guard.json
    evidence_manifest.json
    cycle_NNN/
      cycle_manifest.json
```

The operator fails closed if required evidence is absent, unsafe, malformed, inconsistent, or tampered. It never repairs or rewrites a bundle.

## Status

```powershell
$Python = 'E:\Code\Python\VirtualEnvironments\Blast_Pit\Scripts\python.exe'
$Artifacts = 'E:\Code\Python\VirtualEnvironments\Blast_Pit\_codex_improvement_evidence_2d_Simulator'

& $Python '.\improvement_operator.py' status --artifact-root $Artifacts
& $Python '.\improvement_operator.py' status --artifact-root $Artifacts --json
```

`status` reports execution state separately from review readiness. Successful controller execution does not mean a candidate is ready, promoted, audited, or released. A non-success execution or retained blockers returns exit code `2`.

## Review

```powershell
& $Python '.\improvement_operator.py' review --artifact-root $Artifacts
& $Python '.\improvement_operator.py' review --artifact-root $Artifacts --json
```

Exit `0` requires all of the following in the sealed decision:

- execution `SUCCESS`, review `PASS`, and promotion state `HUMAN_REVIEW_PENDING`;
- no blockers and no production modification;
- a candidate commit and diff hash;
- rubric score 100/100;
- all twelve core gates present and `PASS`;
- one `PASS` artifact for each of seven specialist roles plus final QA;
- `promotion_authorized: false` and `release_authorized: false`.

This means only “ready for a human to review.” A person must still decide whether to reject, request changes, or begin a separately authorized promotion workflow.

The rubric contains ten dimensions worth ten points each. `10/10` is shorthand for all dimensions receiving full credit, hence 100/100; it is unrelated to the requested cycle count.

## Verify

Verify the latest run:

```powershell
& $Python '.\improvement_operator.py' verify --artifact-root $Artifacts
```

Verify a retained non-latest run independently:

```powershell
& $Python '.\improvement_operator.py' verify `
  --artifact-root $Artifacts `
  --run-id 20260711T210000Z
```

Add `--json` for a machine-readable verification result. Verification checks:

- exact outer-manifest file set, sizes, and SHA-256 hashes;
- exact chained cycle-manifest file sets and hashes;
- transition revision sequence, previous hashes, recomputed hashes, and terminal binding to `state.json`;
- production guard and unmodified-production decision;
- run and terminal-state agreement;
- latest manifest and operator-decision hashes for the current run;
- sealing of transition-named evidence.

An explicit historical `--run-id` is verified from its own sealed files and does not need to be the current latest run.

## Exit codes

- `0`: verification passed, or the sealed decision is ready for human review.
- `1`: required root/run/decision evidence is missing, unsafe, or cannot be selected unambiguously.
- `2`: evidence is readable but status/review is blocked or incomplete.
- `3`: evidence is malformed, inconsistent, unsealed, or tampered.

Treat every nonzero result as fail-closed. Read stderr for the exact missing field, failed contract, or mismatched artifact. Do not delete, edit, or reseal retained evidence to make verification pass.

## Terminal-state interpretation

- `DRY_RUN_COMPLETE` maps to execution `NOT_RUN`; review remains blocked by design.
- `COMPLETE` and `COMPLETE_WITH_REJECTIONS` may map to execution `SUCCESS`; only the sealed review decision determines human-review readiness.
- `COMPLETE_WITH_ERRORS`, `ERROR`, and `FAILED` map to execution `FAILED` and remain blocked.
- `TIMEOUT` and `KILLED` remain distinct blocked execution outcomes.

These terminal conventions are emitted by the v2 controller and consumed by the read-only operator.

## Supported launcher modes

```powershell
.\run_codex_improvement_monitor.bat -Mode Run -Cycles 1
.\run_codex_improvement_monitor.bat -Mode DryRun
.\run_codex_improvement_monitor.bat -Mode Recover
.\run_codex_improvement_monitor.bat -Mode Status -Json
.\run_codex_improvement_monitor.bat -Mode Review
.\run_codex_improvement_monitor.bat -Mode Verify -RunId <run-id>
.\run_codex_improvement_monitor.bat -Mode Stop
.\run_codex_improvement_monitor.bat -Mode InspectTerminal -RunId <run-id>
```

InspectTerminal is deliberately terminal-only: it verifies a sealed run and returns its review disposition. It cannot continue a partial run. Stop creates only `.supervisor_stop.codex-improvement-controller-v2`; retain killed evidence and start a new recovery run.

Recover is not a read-only operator command. It acquires the controller kernel lock, removes and verifies absence of governed containers first, then restores persisted ACL leases. It cannot resume a partial run. Container and ACL recovery events are separately sealed and hash-chain ledgered; either latest hazard blocks readiness even when an older run bundle verifies. Use Status and Verify independently after recovery.

The controller evidence root is `_codex_improvement_evidence_2d_Simulator`, candidate worktrees are `_codex_improvement_worktrees_2d_Simulator`, and supervisor evidence is `_codex_light_runner_evidence_2d_Simulator`, all beside the protected checkout.

Run `20260711T223022Z-1128b831` remains an unanchored failed diagnostic example. Supported DryRun runner `20260712T005801Z` resolved latest controller run `20260712T005807Z-709f67a4`, whose sealed decision is `DRY_RUN_COMPLETE`/`NOT_RUN`, not review-ready. It proves preflight, isolation qualification, container quiescence, ACL restoration, production protection, sealing, and local-ledger/latest publication; it does not prove candidate tests, training, scoring, specialist consensus, or final QA. That retained run predates v3.1 supervisor sealing; current qualification is 240 passed with 2 platform skips.

## Security boundary

Verification proves internal consistency of retained files and local run, container-recovery, and ACL-recovery ledgers; it is not a digital signature and does not prove the Docker daemon, host kernel, or operating-system account was uncompromised. Use a dedicated host or VM when stronger host isolation is required.

Runner v3.1 evidence is independently sealed. Use ledger-bound `<name>_terminal.json`, not advisory/live `<name>_state.json`, for terminal disposition. The pointer binds manifest/state hashes and the terminal row's `ledger_hash`; that row records `name_binding_hash`. A pending publication WAL blocks publish-complete verification; startup recovery precedes allocation. Post-v3.1 DryRun runner `20260712T014740Z-04461e70` has no publication WAL and verifies against runner ledger `87bac20f8df9992f041154cdc355aaaa86ad7324a088d0241839988410c187c3` and name binding `7565b161dbf6cfbdc718e456ab990bd72243afbd9d2b9785c00c7aca60cb8bb1`. Controller Verify returned 0; Status/Review returned 1 by design because the DryRun decision is `NOT_RUN`, 0/100, and not review-ready. Local ledgers are tamper evidence, not signatures.

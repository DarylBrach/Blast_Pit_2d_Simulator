# Final QA

## Retained 2026-07-11 evidence

- Active interpreter: `E:\Code\Python\VirtualEnvironments\Blast_Pit\Scripts\python.exe`, Python 3.11.0, NumPy 2.2.0.
- Fast suite: `9 passed` after rebuilding the replaced test module.
- Disposable lifecycle: fresh train, continuation, and concise status completed.
- Exact-load stress: 8 workers completed three disposable 112-task generations, but repeated production/disposable evolved workloads exposed Windows process-pool termination at generation 3; 2 workers later terminated at production generation 8.
- Serial replay committed the same deterministic generation, establishing `--workers 1` as the qualified production path on this interpreter.
- Production `v35-production-001`: generation 9 was committed and the serial continuation proceeded into generation 10 during monitoring. Audit remains `NOT_RUN`; no release claim is authorized.

The following checklist remains release qualification work; unchecked narrative is not evidence of completion.

- Extract into a clean Python 3.11 environment, including a path containing spaces.
- Install `requirements.txt` and run all tests.
- Run the same golden trial twice and compare final-state hashes.
- Compare workers 1 and 2/4 for ordered semantic equivalence.
- Compare uninterrupted and train/continue runs.
- Exercise interrupt recovery and audit/manifest recovery on a disposable experiment.
- Reject corrupted checkpoints, mismatched approval/config/seed/engine, and unsafe experiment IDs.
- Execute README and Operations commands verbatim on Windows.
- Confirm the source contains no network or subprocess calls.
- Record benchmark, ZIP SHA-256, and release inventory.
- Exclude `.venv`, caches, temporary artifacts, and real audit outputs from distribution.

## Improvement harness v2 QA boundary

A v2 result is review-ready only when the root decision is 100/100 with every deterministic gate, all seven specialists, independent final QA, Fold C evaluation, and production protection passing. Status `COMPLETE` alone is insufficient. `COMPLETE_WITH_REJECTIONS` may represent successful controller execution but remains subject to the root decision. No harness QA result authorizes production use or release.

Historical v2.1 QA used the Windows audit-guard evidence described below; it does not qualify v2.2. `10/10` means all ten rubric dimensions received ten points, totaling 100/100, and human review only. Current v2.2 totals and successful supported DryRun evidence remain pending.

For v2.2, the preceding v2.1 audit-guard/count statement is historical. Final QA instead requires the immutable image attestation and recipe, Docker host identity and exact policy, read-only workspace, bounded tmpfs, trusted exporter validation, native canary, lifecycle/quiescence and container recovery, then ACL recovery and exact-SDDL ordering. Final suite totals and successful DryRun are pending. `10/10` remains 100/100 and human review only.

# Troubleshooting

`v35 artifacts already exist`: do not rerun fresh `train`; run `status`, calculate the remaining increment, and use `continue`. `approval record identity/status mismatch`: use the shipped v35 approval or an equivalent reviewed v35 record. `checkpoint ... mismatch`: keep experiment ID, seed, engine, and inference backend identical. `estimated frames exceed work budget`: raise the explicit budget only after reviewing the workload.

`worker evaluation group failed`: the current generation was not committed. If a checkpoint exists, resume it with `continue`; if generation 0 never committed, retain the context files and use a reviewed new experiment ID rather than deleting evidence. Windows multiprocessing failures can also result from removing the `if __name__ == "__main__"` guard.

If the remote traceback reports changing objects such as `range_iterator` or `collections.defaultdict` "is not callable" from otherwise valid spatial-index code, or a worker exits abruptly, verify that the updated source is in use. The corrected worker model sets BLAS/OpenMP limits before NumPy import and does not call `threadpoolctl` inside spawned workers. Retry only from the last committed checkpoint.

Observed 2026-07-11 boundary: Python 3.11.0 on Windows still terminated process pools at 8 workers (generation 3) and later at 2 workers (generation 8), while the serial reference path committed the same deterministic work. Until the base interpreter is upgraded and requalified, use `--workers 1` for production reliability. A worker-count change does not alter the engine fingerprint.

Install into the active interpreter with `python -m pip`, not an ambiguous `pip`. Verify using `python -c "import sys,numba; print(sys.executable, numba.__version__)"`. Numba has first-use JIT/cache overhead and accelerates only the bounded distance kernel in v35, not the full frame. If unavailable, use `--engine python`; v35 never silently substitutes engines and cannot change engine during continuation. If Pygame cannot open a window, update the GPU driver and reinstall Pygame; training does not require a display.

`run_v37_8h.ps1` fails on a dirty worktree: inspect `git status --short`; commit intentional source/docs changes and do not hide unexplained drift. Missing `approval_v37_8h_001.json` or `audit_seeds_v37_8h_001_committed.txt` is an intentional governance stop, not a launcher defect. Generate and review exact scoped inputs; never copy or rename approval from another experiment.

`stale scoped kill switch`: inspect runner state and running processes before removing `.supervisor_stop.robustness-v37-8h-001`. `BUDGET_EXHAUSTED`: confirm checkpoint status, remove no retained artifacts, run the launcher dry-run, then resume with the identical approved generation ceiling. `TIMEOUT` or `KILLED`: verify the full child tree exited and validate the last committed checkpoint before resume. Never audit until status reports `TRAINING_COMPLETE` and zero remaining generations.

## Improvement controller v2

`Run or DryRun rejects a dirty checkout`: inspect `git status --short`; do not hide or discard unexplained changes. `stale v2 stop file`: confirm the previous supervisor stopped before removing `.supervisor_stop.codex-improvement-controller-v2`.

Exit `2` can mean a correctly completed but blocked run, a rejected/no-candidate result, timeout, or controller failure. Run Status and Review for the disposition, then Verify for evidence integrity. Exit `3` from Verify means missing, extra, mismatched, unsafe, or tampered evidence; retain the bundle and do not reseal it manually.

InspectTerminal accepts only an immutable terminal run ID. A partial or killed run cannot continue in place. Preserve it, investigate runner/controller evidence, and start a fresh recovery run. If the local ledger is missing or disagrees, the operator fails closed because the same-machine tamper-evident chain is incomplete.

`ACL recovery required` or an incomplete WAL: do not delete the lease root, edit its ACL, remove the WAL/helper archive, or bypass the kernel controller lock. Run `.\run_codex_improvement_monitor.bat -Mode Recover`. It acquires the lock, validates the fixed paths and lease-pinned helper hash, replays the WAL, and restores/verifies exact SDDL. It bypasses the normal clean-check only for recovery and never resumes candidate work. Every attempt is sealed and recovery-ledgered; `acl_recovery_latest.json` keeps a failed hazard prominent and blocks later Status/Review/Verify readiness and controller startup until a successful recovery supersedes it.

`historical v2.1 sandbox canary failed`: retain the raw/guarded evidence for historical diagnosis, but do not use it to qualify the v2.2 candidate boundary. Current candidate qualification is the Docker preflight and native container canary below.

Run `20260711T223022Z-1128b831` is expected to Verify nonzero because it failed before canary on CLI atomic-delete behavior and is absent from the local ledger. Preserve it as diagnostic evidence; do not manually append it, reseal it, or describe it as a successful DryRun.

`v2.2 container preflight/canary failed`: verify a Linux/amd64 Docker engine, exact attested image, and authorization-bound host identity. Never build or pull during a run. Inspect for non-root, no network, read-only root, all capabilities dropped, one read-only workspace bind, and bounded `/tmp` and `/output` tmpfs. Any native socket, mount, host-read, or root-write success is a hard failure. `candidate export rejected` means unsafe/duplicate path, invalid base64, size/count excess, or SHA-256 mismatch; never copy candidate host paths directly. Recover removes/verifies containers before ACL recovery. Status/Review/Verify surface both hazards.

`jsonschema is required for governed v2 validation`: install the repository requirements with the same interpreter configured in the launcher: `& $Python -m pip install -r .\requirements.txt`. Then rerun the full suite and DryRun; do not bypass schema validation.

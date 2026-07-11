# Testing

Run `run_tests.bat`. The fast suite checks positional CLI parsing, concise status math, actionable/non-mutating collision recovery, scalar/batch inference parity, deterministic simulation hashes, experiment-path containment, and the retained production checkpoint when present.

Release qualification should additionally compare workers 1 and N, uninterrupted versus resumed evolution, repeated golden seeds, corrupt/oversized NPZ rejection, audit idempotency, manifest recovery, Windows spawn, headless visualization, and a 20-generation soak. Benchmark before selecting worker count because process startup can dominate short trials.

Fast pytest success is necessary but does not claim completion of the release/soak checklist. Retain commands, timestamps, interpreter/package versions, exit codes, and artifact hashes for release evidence.

Controller v2 qualification covers authorization/source bindings, tool-less role streaming, Job Object termination, sandbox canary and path containment, build/review/final-QA schemas, cumulative-cycle state, remediation caps, Fold B/C separation, candidate driver/scorer determinism, transition and manifest chains, local ledger verification, and read-only Status/Review/Verify behavior. Platform-dependent Windows containment tests may skip where the required facility is unavailable; skips must be reported, not described as passes.

Install `requirements.txt` into the exact interpreter used for tests and launch. Controller v2 intentionally fails closed without `jsonschema`; schema-validation tests and live role-result validation require it.

Before a governed multi-cycle run, execute the full repository suite and a supported DryRun. Ten cycles are attempts under one time budget; they are not ten test passes or ten guaranteed improvements.

The frozen v2 pre-launch qualification on 2026-07-11 used `E:\Code\Python\VirtualEnvironments\Blast_Pit\Scripts\python.exe`: 188 tests passed in 27.60 seconds. Two reparse-containment tests skipped because this Windows host does not permit symlink creation (`test_improvement_harness_runtime_v2.py:74` and `test_improvement_sandbox_canary.py:96`). Python compilation and PowerShell launcher parsing passed. These skips remain explicit limitations; the supported clean-tree DryRun and its sealed evidence are the operational qualification record.

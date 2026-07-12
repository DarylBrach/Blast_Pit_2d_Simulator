# Testing

Run `run_tests.bat`. The fast suite checks positional CLI parsing, concise status math, actionable/non-mutating collision recovery, scalar/batch inference parity, deterministic simulation hashes, experiment-path containment, and the retained production checkpoint when present.

Release qualification should additionally compare workers 1 and N, uninterrupted versus resumed evolution, repeated golden seeds, corrupt/oversized NPZ rejection, audit idempotency, manifest recovery, Windows spawn, headless visualization, and a 20-generation soak. Benchmark before selecting worker count because process startup can dominate short trials.

Fast pytest success is necessary but does not claim completion of the release/soak checklist. Retain commands, timestamps, interpreter/package versions, exit codes, and artifact hashes for release evidence.

Controller v2.1 qualification covers authorization/source bindings, tool-less role streaming, Job Object termination, kernel-lock exclusion, ACL WAL/startup/emergency recovery, the versioned helper archive, sealed recovery decisions/manifests and recovery ledger/status pointer, exact multiset SID discovery, durable `APPLYING`, exact-SDDL restoration, Python audit-guard socket/process/read/write/delete/rename/link denials, separate raw-versus-guarded canary evidence, build/review/final-QA schemas, cumulative-cycle state, remediation caps, Fold B/C separation, candidate driver/scorer determinism, transition and manifest chains, local ledger verification, and read-only Status/Review/Verify behavior. Platform-dependent Windows containment tests may skip where the required facility is unavailable; skips must be reported, not described as passes.

Install `requirements.txt` into the exact interpreter used for tests and launch. Controller v2 intentionally fails closed without `jsonschema`; schema-validation tests and live role-result validation require it.

Before a governed multi-cycle run, execute the full repository suite and a supported DryRun. Ten cycles are attempts under one time budget; they are not ten test passes or ten guaranteed improvements.

Earlier v2 and v2.1 results predate the final v2.2 Docker boundary and do not qualify it. Current code qualification is 240 passed with 2 reported platform skips. The historical supported clean-tree DryRun is qualified through the exact BAT/CodexLightRunner entrypoint: runner `20260712T005801Z`, controller `20260712T005807Z-709f67a4`, runner return 0, `DRY_RUN_COMPLETE`, container host/canary/quiescence pass, exact ACL restoration pass, production unmodified, and sealed ledger/latest publication; it predates v3.1 supervisor sealing.

First live run `20260711T223022Z-1128b831` failed closed before canary on CLI atomic-delete behavior. It proves failure retention and unchanged production only; because it is unanchored in the local ledger, it is not a passing evidence-verification or DryRun result.

## Controller v2.2 qualification

The v2.1 counts and audit-guard qualification above are historical and do not qualify v2.2. Qualification must cover the attested immutable image, hash-locked recipe, exact Docker policy, read-only workspace bind, bounded 256 MiB `/tmp` and `/output` tmpfs, native canary, lifecycle/recovery/quiescence, and trusted stdout exporter safe-path/base64/per-file-hash/aggregate-bound validation. Compile, focused and complete tests, training, and trusted scoring must all be containerized. Windows audit-guard tests are defense in depth only.

Final current qualification is 240 passed and 2 skipped in 54.66 seconds. The reported skips are `test_safe_remove_tree_preflights_entire_tree_before_deleting` because symlink creation is unavailable and `test_symlink_leaf_and_ancestor_rejected_when_supported` because directory symlinks are unavailable. The focused runner v3.1 suite passes 27 tests covering manifest v2, tamper detection, kernel locks, parallel publication, failure terminalization, WAL recovery at all tested phases, malformed WAL rejection, hash-chain name binding/tamper detection, strict tree/JSON/size checks, child interruption, and encoding resilience. This qualifies process-crash recovery only. A new exact-entrypoint supported DryRun is pending the clean v3.1 commit.
